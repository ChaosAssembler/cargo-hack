// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Support for the `--prioritize` flag.
//!
//! This records a fingerprint of the diagnostics of each cargo command in a
//! cache file, and uses it to execute commands whose diagnostics changed in
//! previous runs earlier in subsequent runs.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use serde_json::{Value, json};

use crate::fs;

/// Incremented whenever the format, the keys, or the fingerprinting algorithm
/// of the cache file changes.
const CACHE_VERSION: u64 = 3;

pub(crate) struct Cache {
    path: PathBuf,
    /// The number of the current run. 1 on the first run.
    run: u64,
    entries: BTreeMap<String, Entry>,
    /// Set after saving the cache failed; further saves are skipped so that a
    /// persistent failure does not produce a warning for every command.
    save_disabled: bool,
}

struct Entry {
    /// Fingerprint of the output of the command in the run it last changed.
    fingerprint: String,
    /// The run number in which the output of the command last changed.
    changed_run: u64,
}

impl Cache {
    /// Loads the cache for the workspace rooted at `workspace_root` from
    /// `target_dir`, treating a missing or corrupt file as an empty cache.
    pub(crate) fn load(target_dir: &Path, workspace_root: &Path) -> Self {
        let path = cache_path(target_dir, workspace_root);
        let (saved_run, entries) =
            fs::read(&path).ok().and_then(|bytes| parse(&bytes)).unwrap_or_default();
        // The current run is the one after the last run recorded in the
        // cache. Entries may have been recorded by a run that was killed
        // before it could save the run number, so also take the maximum
        // changed_run into account; otherwise priorities could go backwards.
        let run = entries.values().map(|e| e.changed_run).max().unwrap_or(0).max(saved_run) + 1;
        Self { path, run, entries, save_disabled: false }
    }

    /// Returns the priority of the command with the given key: the run number
    /// in which its output last changed. Commands that have never been run are
    /// treated as if they changed in the current run.
    pub(crate) fn priority(&self, key: &str) -> u64 {
        self.entries.get(key).map_or(self.run, |entry| entry.changed_run)
    }

    /// Records the output of a command, marking it as changed in the current
    /// run if its output differs from the recorded one. Returns whether the
    /// cache was changed and thus needs to be saved.
    pub(crate) fn record(&mut self, key: &str, output: &[u8]) -> bool {
        let fingerprint = fingerprint(output);
        let entry = self
            .entries
            .entry(key.to_owned())
            .or_insert_with(|| Entry { fingerprint: String::new(), changed_run: 0 });
        if entry.fingerprint == fingerprint {
            false
        } else {
            entry.fingerprint = fingerprint;
            entry.changed_run = self.run;
            true
        }
    }

    /// Saves the cache to disk. Failing to update the cache is not fatal:
    /// only the first failure is reported and further saves are skipped, so
    /// that a persistent failure (e.g., a read-only target directory) does
    /// not produce a warning for every command.
    pub(crate) fn save(&mut self) {
        if self.save_disabled {
            return;
        }
        if let Err(e) = self.try_save() {
            self.save_disabled = true;
            warn!("failed to update cache file {}: {e:#}", self.path.display());
        }
    }

    fn try_save(&self) -> Result<()> {
        let mut entries = serde_json::Map::new();
        for (key, entry) in &self.entries {
            entries.insert(
                key.clone(),
                json!({ "fingerprint": entry.fingerprint, "changed_run": entry.changed_run }),
            );
        }
        let doc = json!({ "version": CACHE_VERSION, "run": self.run, "entries": entries });
        let dir = self.path.parent().context("cache path has no parent")?;
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create directory `{}`", dir.display()))?;
        // Write to a temporary file and rename it so that the cache file is
        // never left in a partially written state (e.g., if the process is
        // killed during the write).
        let tmp = dir.join(format!(
            ".{}.{}.tmp",
            self.path.file_name().unwrap_or_default().to_string_lossy(),
            std::process::id(),
        ));
        fs::write(&tmp, serde_json::to_vec(&doc)?)?;
        if let Err(e) = std::fs::rename(&tmp, &self.path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| {
                format!("failed to rename `{}` to `{}`", tmp.display(), self.path.display())
            });
        }
        Ok(())
    }
}

/// The cache file is scoped by workspace root so that workspaces sharing a
/// target directory do not share a cache (the keys are workspace-relative).
fn cache_path(target_dir: &Path, workspace_root: &Path) -> PathBuf {
    target_dir.join("cargo-hack").join(format!(
        "prioritize-{:016x}.json",
        fnv1a(workspace_root.to_string_lossy().as_bytes()),
    ))
}

fn parse(bytes: &[u8]) -> Option<(u64, BTreeMap<String, Entry>)> {
    let doc: Value = serde_json::from_slice(bytes).ok()?;
    if doc.get("version")?.as_u64()? != CACHE_VERSION {
        // Cache created by an incompatible version of cargo-hack; start over.
        return None;
    }
    let run = doc.get("run").and_then(Value::as_u64).unwrap_or(0);
    let mut entries = BTreeMap::new();
    if let Some(obj) = doc.get("entries").and_then(Value::as_object) {
        for (key, entry) in obj {
            if let (Some(fingerprint), Some(changed_run)) = (
                entry.get("fingerprint").and_then(Value::as_str),
                entry.get("changed_run").and_then(Value::as_u64),
            ) {
                entries.insert(key.clone(), Entry {
                    fingerprint: fingerprint.to_owned(),
                    changed_run,
                });
            }
        }
    }
    Some((run, entries))
}

/// Computes the fingerprint of the output of a cargo command.
///
/// Volatile parts of the output (color escape sequences, durations, cargo's
/// status lines, and non-diagnostic cargo JSON messages) are excluded so that
/// only changes to the actual output (e.g., diagnostics) are detected.
fn fingerprint(output: &[u8]) -> String {
    format!("{:016x}", fnv1a(&normalize(output)))
}

fn normalize(output: &[u8]) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    for line in output.split(|&b| b == b'\n') {
        let line = strip_ansi(line);
        // Strip `\r` in case the output was written with CRLF line endings.
        let line = line.strip_suffix(b"\r").unwrap_or(&line);
        if line.is_empty() {
            continue;
        }
        match parse_json_line(line) {
            // A cargo JSON message that does not carry diagnostics (e.g.,
            // compiler-artifact messages, which contain build paths and
            // freshness flags that change between runs).
            JsonLine::Message => {}
            // Rendered diagnostics of a compiler-message.
            JsonLine::Rendered(rendered) => {
                for line in rendered.split('\n') {
                    let stripped = strip_ansi(line.as_bytes());
                    let line = stripped.strip_suffix(b"\r").unwrap_or(&stripped);
                    if !line.is_empty() {
                        lines.push(line.to_vec());
                    }
                }
            }
            JsonLine::NotJson => {
                let line = trim_duration(line);
                // Cargo indents its status lines (e.g., `    Finished ...`).
                let trimmed = line.iter().position(|&b| b != b' ' && b != b'\t');
                if trimmed.is_none_or(|i| is_status_line(&line[i..])) {
                    continue;
                }
                lines.push(line.to_vec());
            }
        }
    }
    // Sort so that the fingerprint does not depend on the order in which
    // parallel rustc invocations emit their diagnostics.
    lines.sort();
    let mut normalized = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if i != 0 {
            normalized.push(b'\n');
        }
        normalized.extend_from_slice(line);
    }
    normalized
}

enum JsonLine {
    /// Not a cargo JSON message.
    NotJson,
    /// A cargo JSON message without diagnostics.
    Message,
    /// A `compiler-message` with its rendered diagnostics.
    Rendered(String),
}

fn parse_json_line(line: &[u8]) -> JsonLine {
    if !line.starts_with(b"{") {
        return JsonLine::NotJson;
    }
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return JsonLine::NotJson;
    };
    let Some(reason) = value.get("reason").and_then(Value::as_str) else {
        return JsonLine::NotJson;
    };
    if reason != "compiler-message" {
        return JsonLine::Message;
    }
    match value.get("message").and_then(|m| m.get("rendered")).and_then(Value::as_str) {
        Some(rendered) => JsonLine::Rendered(rendered.to_owned()),
        None => JsonLine::Message,
    }
}

/// Strips ANSI escape sequences (e.g., color codes) from a line.
fn strip_ansi(line: &[u8]) -> Vec<u8> {
    let mut stripped = Vec::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        if line[i] == 0x1B {
            if i + 1 < line.len() && line[i + 1] == b'[' {
                // CSI sequence: skip until a final byte (0x40..=0x7e).
                i += 2;
                while i < line.len() && !(0x40..=0x7E).contains(&line[i]) {
                    i += 1;
                }
                i += 1;
            } else {
                i += 1;
            }
        } else {
            stripped.push(line[i]);
            i += 1;
        }
    }
    stripped
}

/// Strips a trailing duration (e.g., ` in 1.23s`) from a line.
fn trim_duration(line: &[u8]) -> &[u8] {
    if let Some(pos) = line.windows(4).rposition(|w| w == b" in ") {
        if is_duration(&line[pos + 4..]) {
            return &line[..pos];
        }
    }
    line
}

/// Returns whether `s` is a duration like `1.23s` or `1s`.
fn is_duration(s: &[u8]) -> bool {
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return false;
    }
    let mut s = &s[digits..];
    if s.first() == Some(&b'.') {
        s = &s[1..];
        let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return false;
        }
        s = &s[digits..];
    }
    s == b"s"
}

/// Lines printed by cargo that do not carry any result of the command
/// (e.g., progress indicators and build paths that change between runs).
const STATUS_PREFIXES: &[&[u8]] = &[
    b"Blocking waiting",
    b"Checking ",
    b"Compiling ",
    b"Downloading ",
    b"Downloaded ",
    b"Finished",
    b"Fresh ",
    b"Locking ",
    b"Adding ",
    b"Removing ",
    b"Running ",
    b"Updating ",
];

fn is_status_line(line: &[u8]) -> bool {
    STATUS_PREFIXES.iter().any(|prefix| line.starts_with(prefix))
}

/// FNV-1a: a small hash function with a stable output across runs and
/// platforms (unlike `std::collections::hash_map::DefaultHasher`).
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xCBF2_9CE4_8422_2325_u64;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_human_output() {
        let output = concat!(
            "\x1b[33m",
            "warning",
            "\x1b[0m: unused\n    Finished `dev` profile in 0.01s\n\n"
        );
        assert_eq!(normalize(output.as_bytes()), b"warning: unused".to_vec());
        assert_eq!(normalize(b"error: failed in 1.23s"), b"error: failed".to_vec());
    }

    #[test]
    fn normalize_json_output() {
        let artifact = r#"{"reason":"compiler-artifact","fresh":false,"filename":"/tmp/abc.rlib"}"#;
        let message = r#"{"reason":"compiler-message","message":{"rendered":"warning: unused\n"}}"#;
        let without_rendered = r#"{"reason":"compiler-message","message":{}}"#;
        let not_cargo = r#"{"foo":1}"#;
        let output = format!("{artifact}\n{message}\n{without_rendered}\n{not_cargo}\n");
        // Only the rendered diagnostics of compiler-message are kept.
        assert_eq!(normalize(output.as_bytes()), b"warning: unused\n{\"foo\":1}".to_vec());
    }

    #[test]
    fn fingerprint_is_order_insensitive() {
        let a = b"warning: A\nwarning: B\n";
        let b = b"warning: B\nwarning: A\n";
        assert_eq!(fingerprint(a), fingerprint(b));
        assert_ne!(fingerprint(a), fingerprint(b"warning: A\n"));
    }

    #[test]
    fn cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Path::new("/workspace");
        let mut cache = Cache::load(dir.path(), ws);
        // Never-seen commands have the priority of the current run.
        assert_eq!(cache.priority("cmd"), 1);
        assert!(cache.record("cmd", b"out"));
        cache.save();
        // No temporary file is left behind.
        let files: Vec<_> = std::fs::read_dir(dir.path().join("cargo-hack"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files.len(), 1);

        let mut cache = Cache::load(dir.path(), ws);
        assert_eq!(cache.priority("cmd"), 1);
        // Unchanged output does not change the cache.
        assert!(!cache.record("cmd", b"out"));
        // Changed output is recorded in the new run.
        assert!(cache.record("cmd", b"out2"));
        assert_eq!(cache.priority("cmd"), 2);
    }

    #[test]
    fn cache_ignores_corrupt_or_incompatible_file() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Path::new("/workspace");
        let path = cache_path(dir.path(), ws);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        std::fs::write(&path, b"{ not json").unwrap();
        assert_eq!(Cache::load(dir.path(), ws).priority("x"), 1);

        let future = format!(r#"{{"version":{},"run":7,"entries":{{}}}}"#, CACHE_VERSION + 1);
        std::fs::write(&path, future).unwrap();
        assert_eq!(Cache::load(dir.path(), ws).priority("x"), 1);
    }

    #[test]
    fn cache_run_after_killed_run() {
        // A killed run can leave entries with a run number higher than the
        // saved run number; priorities must not go backwards.
        let dir = tempfile::tempdir().unwrap();
        let ws = Path::new("/workspace");
        let path = cache_path(dir.path(), ws);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!(
                r#"{{"version":{CACHE_VERSION},"run":3,"entries":{{"cmd":{{"fingerprint":"abc","changed_run":5}}}}}}"#
            ),
        )
        .unwrap();
        let cache = Cache::load(dir.path(), ws);
        assert_eq!(cache.priority("cmd"), 5);
        assert_eq!(cache.priority("other"), 6);
    }

    #[test]
    fn cache_stops_saving_after_first_failure() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Path::new("/workspace");
        let path = cache_path(dir.path(), ws);
        let mut cache = Cache::load(dir.path(), ws);
        assert!(cache.record("cmd", b"out"));
        // Make the first save fail: a file exists where the cache directory
        // should be.
        std::fs::write(path.parent().unwrap(), b"").unwrap();
        cache.save();
        // After the first failure, further saves are skipped even when they
        // would succeed, so that a persistent failure does not produce a
        // warning for every command.
        std::fs::remove_file(path.parent().unwrap()).unwrap();
        cache.save();
        assert!(!path.exists());
    }

    #[test]
    fn cache_path_scoped_by_workspace() {
        assert_ne!(
            cache_path(Path::new("/t"), Path::new("/a")),
            cache_path(Path::new("/t"), Path::new("/b"))
        );
        assert_eq!(
            cache_path(Path::new("/t"), Path::new("/a")),
            cache_path(Path::new("/t"), Path::new("/a"))
        );
    }
}
