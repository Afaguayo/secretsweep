//! Walks a directory (respecting `.gitignore`) and runs the detectors
//! over every text file, line by line.

use crate::detectors::{self, Finding};
use ignore::WalkBuilder;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Hit {
    pub path: PathBuf,
    pub line_number: usize,
    pub finding: Finding,
}

pub struct ScanConfig {
    pub entropy_threshold: f64,
    pub min_token_len: usize,
    pub include_entropy: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 4.0,
            min_token_len: 20,
            include_entropy: true,
        }
    }
}

/// Scans `root` and returns every finding, sorted by path then line.
pub fn scan_directory(root: &Path, config: &ScanConfig) -> Vec<Hit> {
    let mut hits = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(false) // still skip VCS dirs via .gitignore, but don't skip dotfiles outright
        .git_ignore(true)
        .git_exclude(true)
        .require_git(false) // honor .gitignore even when root isn't an actual git repo
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        if is_probably_binary(path) {
            continue;
        }
        let Ok(contents) = fs::read_to_string(path) else {
            continue; // skip unreadable/binary files
        };
        hits.extend(scan_text(path, &contents, config));
    }

    hits.sort_by(|a, b| a.path.cmp(&b.path).then(a.line_number.cmp(&b.line_number)));
    hits
}

fn scan_text(path: &Path, contents: &str, config: &ScanConfig) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        let line_number = i + 1;

        for finding in detectors::scan_line_regex(line) {
            hits.push(Hit { path: path.to_path_buf(), line_number, finding });
        }

        if config.include_entropy {
            for (col, token) in detectors::candidate_tokens(line, config.min_token_len) {
                if detectors::is_high_entropy(token, config.entropy_threshold) {
                    hits.push(Hit {
                        path: path.to_path_buf(),
                        line_number,
                        finding: Finding {
                            rule: "high-entropy-string",
                            redacted: detectors::redact(token),
                            column: col,
                        },
                    });
                }
            }
        }
    }
    hits
}

/// Cheap binary-file heuristic: skip common binary extensions and any
/// file whose first kilobyte contains a NUL byte.
fn is_probably_binary(path: &Path) -> bool {
    const BINARY_EXTENSIONS: &[&str] = &[
        "png", "jpg", "jpeg", "gif", "ico", "pdf", "zip", "tar", "gz", "exe", "dll", "so", "dylib",
        "class", "jar", "woff", "woff2", "ttf", "bin",
    ];
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
            return true;
        }
    }
    if let Ok(bytes) = fs::read(path) {
        let sample = &bytes[..bytes.len().min(1024)];
        return sample.contains(&0);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn finds_secret_in_a_scanned_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.env");
        let mut f = fs::File::create(&file_path).unwrap();
        writeln!(f, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").unwrap();

        let hits = scan_directory(dir.path(), &ScanConfig::default());
        assert!(hits.iter().any(|h| h.finding.rule == "aws-access-key-id"));
    }

    #[test]
    fn respects_gitignore() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored.env\n").unwrap();
        fs::write(dir.path().join("ignored.env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        fs::write(dir.path().join("checked.env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();

        let hits = scan_directory(dir.path(), &ScanConfig::default());
        assert!(hits.iter().all(|h| !h.path.ends_with("ignored.env")));
        assert!(hits.iter().any(|h| h.path.ends_with("checked.env")));
    }

    #[test]
    fn skips_binary_files() {
        let dir = tempdir().unwrap();
        let bin_path = dir.path().join("blob.bin");
        fs::write(&bin_path, [0u8, 1, 2, 3, b'A', b'K', b'I', b'A']).unwrap();

        let hits = scan_directory(dir.path(), &ScanConfig::default());
        assert!(hits.is_empty());
    }

    #[test]
    fn clean_file_produces_no_hits() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() { println!(\"hello\"); }\n").unwrap();

        let hits = scan_directory(dir.path(), &ScanConfig::default());
        assert!(hits.is_empty());
    }
}
