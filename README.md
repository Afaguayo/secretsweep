# secretsweep

[![CI](https://github.com/Afaguayo/secretsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/Afaguayo/secretsweep/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A fast, `.gitignore`-aware secret scanner for a repo or directory, written
in Rust. Catches well-known credential formats via regex **and** flags
high-entropy strings the regexes miss.

## Download

Prebuilt binaries (Linux, macOS Intel/Apple Silicon, Windows `.exe`) are
published on every tagged release:
**[Download the latest release](https://github.com/Afaguayo/secretsweep/releases/latest)**.

## Why

Tools like `gitleaks` and `trufflehog` do this at scale; `secretsweep` is a
focused, dependency-light reimplementation to understand exactly how
detection works — specifically, that regex rules alone miss randomly
generated secrets that don't match a known vendor prefix, which is why
this adds a Shannon-entropy pass on top.

## How it works

1. **Walk** — uses the [`ignore`](https://docs.rs/ignore) crate (the same
   engine ripgrep uses) to walk a directory tree while respecting
   `.gitignore` and `.git/info/exclude`, skipping binary files by
   extension and by sniffing for NUL bytes.
2. **Regex rules** — each line is checked against patterns for AWS access
   keys, AWS secret keys, GitHub tokens (`ghp_`/`gho_`/... /`github_pat_`),
   Slack tokens (`xox[baprs]-`), PEM private key headers, and a generic
   `api_key = "..."` / `secret = "..."` / `token = "..."` assignment
   pattern.
3. **Entropy pass** — every quoted string literal of at least
   `--min-token-len` characters has its Shannon entropy (bits/char)
   computed. Random API keys and base64 blobs cluster well above 4
   bits/char; ordinary words and identifiers cluster lower because
   natural language and typical code tokens repeat characters far more
   than a cryptographically random string does.
4. **Redact** — every finding is printed with the middle of the secret
   masked (`AKIA************MPLE`), so the report is useful without being
   a leak of its own.

## Build from source

Requires a stable Rust toolchain (`rustup`).

```bash
cargo build --release
```

## Usage

```bash
./target/release/secretsweep /path/to/repo
```

```
secretsweep found 5 potential secret(s):

  tests/fixtures/leaky-config.env:3:18  [aws-access-key-id]  AKIA************MPLE
  tests/fixtures/leaky-config.env:4:0   [aws-secret-access-key]  aws_********************KEY"
  tests/fixtures/leaky-config.env:5:13  [github-token]  ghp_********************stuv
  tests/fixtures/leaky-config.env:6:21  [slack-token]  xoxb********************zzzz
  tests/fixtures/leaky-config.env:6:14  [generic-api-key-assignment]  TOKE********************aaa"

5 finding(s) across 5 rule type(s). Review each before assuming it's a false positive.
```

A fake, clearly-labeled demo fixture with intentionally leaky-looking
(but not real) credentials lives at `tests/fixtures/leaky-config.env` — try
it with `secretsweep tests/fixtures`.

Exit code is `2` when findings are present and `0` when clean, so it
drops straight into a pre-commit hook or CI step.

### Options

| Flag | Default | Meaning |
|---|---|---|
| `[path]` | `.` | Directory to scan |
| `--no-entropy` | off | Regex rules only, skip entropy screening |
| `--entropy-threshold <f>` | 4.0 | Bits/char above which a token is flagged |
| `--min-token-len <n>` | 20 | Minimum quoted-token length considered for entropy screening |
| `--json` | off | JSON output |

## Tests

```bash
cargo test
```

15 tests cover every regex rule individually, the entropy function on
known inputs (repeated characters → 0 bits/char; random-looking tokens →
high bits/char), `.gitignore` respecting, binary-file skipping, and a
clean-file-produces-no-hits sanity check.

## Limitations

- Entropy screening only looks inside quoted string literals — a secret
  concatenated at runtime or split across lines won't be caught.
- No history scanning (unlike `gitleaks`/`trufflehog`, which can walk
  git history for secrets that were later removed from HEAD).
- False positives are expected on genuinely random-looking but harmless
  strings (hashes, UUIDs in test fixtures, etc.) — this is a triage aid,
  not a guarantee.

## License

MIT — see [LICENSE](LICENSE).
