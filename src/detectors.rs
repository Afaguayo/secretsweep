//! Secret detectors: a set of regex rules for well-known credential
//! formats, plus a generic Shannon-entropy check that catches
//! high-entropy tokens the regexes miss (random API keys, base64 blobs
//! assigned to suspicious-looking variable names, etc).

use once_cell::sync::Lazy;
use regex::Regex;

/// A single detected secret-like token.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule: &'static str,
    /// The matched text, already redacted for display.
    pub redacted: String,
    /// Byte offset within the line where the match starts.
    pub column: usize,
}

struct Rule {
    name: &'static str,
    pattern: &'static Lazy<Regex>,
}

static AWS_ACCESS_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").unwrap());

static AWS_SECRET_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#).unwrap()
});

static GITHUB_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b").unwrap());

static SLACK_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b").unwrap());

static GENERIC_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*['"]([A-Za-z0-9_\-./+]{16,})['"]"#)
        .unwrap()
});

static PRIVATE_KEY_BLOCK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap());

static RULES: &[Rule] = &[
    Rule { name: "aws-access-key-id", pattern: &AWS_ACCESS_KEY },
    Rule { name: "aws-secret-access-key", pattern: &AWS_SECRET_KEY },
    Rule { name: "github-token", pattern: &GITHUB_TOKEN },
    Rule { name: "slack-token", pattern: &SLACK_TOKEN },
    Rule { name: "generic-api-key-assignment", pattern: &GENERIC_API_KEY },
    Rule { name: "private-key-block", pattern: &PRIVATE_KEY_BLOCK },
];

/// Runs every regex rule against a line, returning one `Finding` per match.
pub fn scan_line_regex(line: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in RULES {
        for m in rule.pattern.find_iter(line) {
            findings.push(Finding {
                rule: rule.name,
                redacted: redact(m.as_str()),
                column: m.start(),
            });
        }
    }
    findings
}

/// Shannon entropy in bits per character of `s`.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let len = s.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// A token-like candidate for entropy screening: a contiguous run of
/// "identifier-ish" characters (alnum, `+/=_-.`) at least `min_len` long,
/// extracted from quoted string literals so we don't flag whole sentences.
pub fn candidate_tokens(line: &str, min_len: usize) -> Vec<(usize, &str)> {
    static QUOTED: Lazy<Regex> = Lazy::new(|| Regex::new(r#"['"]([A-Za-z0-9+/=_.\-]+)['"]"#).unwrap());
    QUOTED
        .captures_iter(line)
        .filter_map(|c| {
            let m = c.get(1)?;
            if m.as_str().len() >= min_len {
                Some((m.start(), m.as_str()))
            } else {
                None
            }
        })
        .collect()
}

/// Flags a token as high-entropy if it's long enough and its Shannon
/// entropy per character exceeds `threshold` (bits/char). 4.0+ is a solid
/// line for base64/hex secrets; plain English text sits around 3.5-4.0
/// bits/char at the word level but much lower for typical code tokens.
pub fn is_high_entropy(token: &str, threshold: f64) -> bool {
    token.len() >= 20 && shannon_entropy(token) >= threshold
}

/// Redacts a matched secret for safe display: keeps a short prefix/suffix
/// and masks the middle, so the finding is still traceable without being
/// a usable copy of the secret.
pub fn redact(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}{}{suffix}", "*".repeat((chars.len() - 8).min(20)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_access_key() {
        let line = r#"aws_key = "AKIAIOSFODNN7EXAMPLE""#;
        let findings = scan_line_regex(line);
        assert!(findings.iter().any(|f| f.rule == "aws-access-key-id"));
    }

    #[test]
    fn detects_github_token() {
        let line = "export GH_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let findings = scan_line_regex(line);
        assert!(findings.iter().any(|f| f.rule == "github-token"));
    }

    #[test]
    fn detects_slack_token() {
        // Deliberately not a real/plausible Slack token shape (letters only,
        // no digit groups) so it exercises the regex without resembling a
        // credential a secret scanner would flag as real.
        let line = r#"token: "xoxb-notarealtoken-zzzzzzzzzzzzzzzz""#;
        let findings = scan_line_regex(line);
        assert!(findings.iter().any(|f| f.rule == "slack-token"));
    }

    #[test]
    fn detects_generic_api_key_assignment() {
        let line = r#"API_KEY="not-a-real-key-zzzzzzzzzzzzzzzz""#;
        let findings = scan_line_regex(line);
        assert!(findings.iter().any(|f| f.rule == "generic-api-key-assignment"));
    }

    #[test]
    fn detects_private_key_block() {
        let line = "-----BEGIN RSA PRIVATE KEY-----";
        let findings = scan_line_regex(line);
        assert!(findings.iter().any(|f| f.rule == "private-key-block"));
    }

    #[test]
    fn does_not_flag_ordinary_code() {
        let line = "let count = items.iter().filter(|x| x.is_valid()).count();";
        let findings = scan_line_regex(line);
        assert!(findings.is_empty());
    }

    #[test]
    fn entropy_of_repeated_char_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn entropy_of_random_looking_token_is_high() {
        let token = "aZ9kLp2QxR7mNw4VtY8sB1cD6fG3hJ0";
        assert!(shannon_entropy(token) > 3.5);
    }

    #[test]
    fn high_entropy_flags_random_tokens_but_not_repetitive_identifiers() {
        let random_b64 = "aZ9kLp2QxR7mNw4VtY8sB1cD6fG3hJ0kLm5";
        assert!(is_high_entropy(random_b64, 3.5));

        // A repetitive, low-alphabet identifier-like string (the kind that
        // shows up constantly in real code) should sit well below a random
        // high-entropy secret.
        let repetitive = "aaaa_bbbb_cccc_dddd_eeee_ffff_gggg_hhhh_iiii_jjjj";
        assert!(shannon_entropy(repetitive) < shannon_entropy(random_b64));
        assert!(!is_high_entropy(repetitive, 4.0));
    }

    #[test]
    fn candidate_tokens_extracts_quoted_strings_above_min_length() {
        let line = r#"let short = "hi"; let long = "abcdefghijklmnopqrst";"#;
        let tokens = candidate_tokens(line, 16);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].1, "abcdefghijklmnopqrst");
    }

    #[test]
    fn redact_keeps_prefix_and_suffix() {
        let redacted = redact("AKIAIOSFODNN7EXAMPLE");
        assert!(redacted.starts_with("AKIA"));
        assert!(redacted.ends_with("MPLE"));
        assert!(redacted.contains('*'));
    }
}
