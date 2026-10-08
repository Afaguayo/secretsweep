use clap::Parser;
use secretsweep::scanner::{scan_directory, ScanConfig};
use std::path::PathBuf;
use std::process::ExitCode;

/// secretsweep - scans a directory for likely leaked secrets using regex
/// rules (AWS/GitHub/Slack tokens, private key blocks, generic api_key=
/// assignments) plus a Shannon-entropy check for high-entropy strings the
/// regexes miss. Respects .gitignore.
#[derive(Parser, Debug)]
#[command(name = "secretsweep", version, about)]
struct Args {
    /// Directory to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Disable the entropy-based detector (regex rules only)
    #[arg(long)]
    no_entropy: bool,

    /// Entropy threshold in bits/char above which a quoted token is flagged
    #[arg(long, default_value_t = 4.0)]
    entropy_threshold: f64,

    /// Minimum token length considered for entropy screening
    #[arg(long, default_value_t = 20)]
    min_token_len: usize,

    /// Emit JSON instead of a human-readable report
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let config = ScanConfig {
        entropy_threshold: args.entropy_threshold,
        min_token_len: args.min_token_len,
        include_entropy: !args.no_entropy,
    };

    let hits = scan_directory(&args.path, &config);

    if args.json {
        print_json(&hits);
    } else {
        print_report(&hits);
    }

    if hits.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn print_report(hits: &[secretsweep::scanner::Hit]) {
    if hits.is_empty() {
        println!("No likely secrets found.");
        return;
    }
    println!("secretsweep found {} potential secret(s):\n", hits.len());
    for hit in hits {
        println!(
            "  {}:{}:{}  [{}]  {}",
            hit.path.display(),
            hit.line_number,
            hit.finding.column,
            hit.finding.rule,
            hit.finding.redacted
        );
    }
    let unique_rules: std::collections::HashSet<_> = hits.iter().map(|h| h.finding.rule).collect();
    println!(
        "\n{} finding(s) across {} rule type(s). Review each before assuming it's a false positive.",
        hits.len(),
        unique_rules.len()
    );
}

fn print_json(hits: &[secretsweep::scanner::Hit]) {
    print!("[");
    for (i, hit) in hits.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!(
            "{{\"path\":{:?},\"line\":{},\"column\":{},\"rule\":{:?},\"redacted\":{:?}}}",
            hit.path.display().to_string(),
            hit.line_number,
            hit.finding.column,
            hit.finding.rule,
            hit.finding.redacted
        );
    }
    println!("]");
}
