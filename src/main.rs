// ----------------- hg ----------------- //
//
//
// -------------------------------------- //

// ----------------- Dependencies ----------------- //
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::process::{Command, ExitCode};

use unicode_normalization::UnicodeNormalization;
use unicode_skeleton::UnicodeSkeleton;

// ----------------- CLI ----------------- //

// Cli struct for parsing command line arguments
#[derive(Parser)]
#[command(name = "hg", about = "Homograph / Unicode confusable guard")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

// Cmd enum for subcommands
#[derive(Subcommand)]
enum Cmd {
    /// Scan a string and report Unicode homograph risk
    Scan {
        text: String,

        /// Print human-readable output (default is JSON)
        #[arg(long)]
        human: bool,
    },

    /// Scan a command, then run it only if allowed
    Run {
        /// Override denial and execute anyway
        #[arg(long)]
        allow: bool,

        /// Print human-readable output (default is JSON)
        #[arg(long)]
        human: bool,

        /// Command and arguments (everything after --)
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
}

// ----------------- Core data model ----------------- //

// ScanReport struct for containing scan results
#[derive(Debug, serde::Serialize)]
struct ScanReport {
    sections: Vec<SectionReport>,
    findings: Vec<Finding>,
    decision: Decision,
}

// SectionReport struct for containing section results
#[derive(Debug, serde::Serialize)]
struct SectionReport {
    original: String,
    nfc: String,
    nfkc: String,
    skeleton: String,
    idna: Option<String>,
}

// Finding struct for containing finding results
#[derive(Debug, serde::Serialize)]
struct Finding {
    level: Level,
    kind: &'static str,
    detail: String,
}

// Level enum for containing severity levels
#[derive(Debug, serde::Serialize, Clone, Copy, PartialEq, Eq)]
enum Level {
    Info,
    Warn,
    High,
}

// Decision enum for containing decision results
#[derive(Debug, serde::Serialize, Clone, Copy)]
enum Decision {
    Allow,
    Warn,
    Deny,
    Info,
}

// ----- Hidden and malicious Unicode -----
// Expected behavior:
// - Return true if the character is a hidden or malicious Unicode character
// - Return false otherwise
fn is_dangerous_format_or_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{202A}' | // LRE
        '\u{202B}' | // RLE
        '\u{202D}' | // LRO
        '\u{202E}' | // RLO
        '\u{202C}' | // PDF
        '\u{2066}' | // LRI
        '\u{2067}' | // RLI
        '\u{2068}' | // FSI
        '\u{2069}' | // PDI
        '\u{200E}' | // LRM
        '\u{200F}' | // RLM
        '\u{200B}' | // ZWNBSP
        '\u{200C}' | // ZWNJ
        '\u{200D}' | // ZWJ
        '\u{FEFF}' | // BOM
        '\u{00AD}' // soft hyphen
    )
}

// ----- Mixed scripts Unicode lookup-----
// Expected behavior:
// - Return Type of script
fn script_bucket(c: char) -> &'static str {
    let u = c as u32;
    if c.is_ascii_alphabetic() {
        "Latin"
    } else if (0x0400..=0x04FF).contains(&u) {
        "Cyrillic"
    } else if (0x0370..=0x03FF).contains(&u) {
        "Greek"
    } else if c.is_ascii_digit()
        || matches!(
            c,
            '-' | '_'
                | '.'
                | '@'
                | '/'
                | ':'
                | ' '
                | '$'
                | '%'
                | '*'
                | '+'
                | '?'
                | '='
                | '&'
                | '#'
                | '!'
        )
    {
        "Common"
    } else {
        "Other"
    }
}

// ---- Mixed scripts detection -----
// Expected behavior:
// - Return None if no mixed scripts
// - Return Some with a message if mixed scripts are found
fn mixed_script(s: &str) -> Option<String> {
    use std::collections::BTreeSet;
    let mut scripts = BTreeSet::new();
    for c in s.chars() {
        let b = script_bucket(c);
        if b != "Common" {
            scripts.insert(b);
        }
    }
    if scripts.len() > 1 {
        Some(format!("Mixed scripts: {:?}", scripts))
    } else if scripts.len() == 1 && !scripts.contains("Latin") {
        Some(format!("Non-Latin script: {}", scripts.first().unwrap()))
    } else {
        None
    }
}

// ---- Scan string -----
// Expected behavior:
// - Return a tuple of (findings, views)
// - findings is a vector of findings
// - views is a struct containing the original string and its normalized forms
fn scan_string(s: &str) -> (Vec<Finding>, SectionReport) {
    let nfc = s.nfc().collect::<String>();
    let nfkc = s.nfkc().collect::<String>();
    let skeleton = s.skeleton_chars().collect::<String>();

    let mut findings = vec![];

    // ---- NFKC detection -----
    //  NFKC is a normalization form that is used to normalize strings to a standard form
    if nfkc != s {
        findings.push(Finding {
            level: Level::Warn,
            kind: "nfkc_changes",
            detail: format!("NFKC changes input: {} -> {}", s, nfkc),
        });
    }

    // ---- Skeleton detection -----
    //  Skeleton is a normalization form that is used to normalize strings to a standard form
    if skeleton != s {
        findings.push(Finding {
            level: Level::Warn,
            kind: "skeleton_changes",
            detail: format!("Skeleton changes input: {} -> {}", s, skeleton),
        });
    }

    // ---- Non-Latin sciipt and Mixed scripts detection -----
    if let Some(m) = mixed_script(s) {
        // Check if the message from the helper indicates a MIXED attack
        if m.starts_with("Mixed scripts") {
            findings.push(Finding {
                level: Level::High,
                kind: "mixed_script",
                detail: m,
            });
        }
        // Otherwise, it must be a Single Non-Latin script
        else {
            findings.push(Finding {
                level: Level::Info,
                kind: "non_latin_script",
                detail: m,
            });
        }
    }

    // ---- Bidi detection -----
    //  Bidi characters are used to control the direction of text in a document
    let mut bidi_hits = vec![];
    for c in s.chars() {
        if is_dangerous_format_or_bidi(c) {
            bidi_hits.push(format!("{} (U+{:04X})", c, c as u32));
        }
    }

    if !bidi_hits.is_empty() {
        findings.push(Finding {
            level: Level::High,
            kind: "format_or_bidi_chars",
            detail: format!("contains: {}", bidi_hits.join(", ")),
        });
    }

    // ---- Domain view (optional)-----
    // Domain views show punycode if domain-like
    let idna = match idna::domain_to_ascii(s) {
        Ok(alabel) => Some(alabel),
        Err(_) => {
            findings.push(Finding {
                level: Level::Warn,
                kind: "idna_failed",
                detail: "IDNA processing failed".to_string(),
            });
            None
        }
    };

    // ---- Views -----
    // Views are used to show the original string and its normalized forms
    let views = SectionReport {
        original: s.to_string(),
        nfc,
        nfkc,
        skeleton,
        idna,
    };
    (findings, views)
}

// ----- Decision -----
// Expected behavior:
// - Return Allow if no findings
// - Return Warn if any findings are Warn
// - Return Deny if any findings are High
fn decision(findings: &[Finding]) -> Decision {
    // Fail-closed: any High => Deny; else any Warn => Warn; else Allow
    if findings.iter().any(|f| f.level == Level::High) {
        Decision::Deny
    } else if findings.iter().any(|f| f.level == Level::Warn) {
        Decision::Warn
    } else if findings.iter().any(|f| f.level == Level::Info) {
        Decision::Info
    } else {
        Decision::Allow
    }
}

// ----- Scan Sections ----- //
// Expected behavior:
// - Return a ScanReport containing the findings and decision
fn scan_sections(sections: &[String]) -> ScanReport {
    let mut all_findings = Vec::new();
    let mut section_reports = Vec::new();

    for t in sections {
        let (findings, section) = scan_string(t);
        all_findings.extend(findings);
        section_reports.push(section);
    }

    let decision = decision(&all_findings);

    ScanReport {
        sections: section_reports,
        findings: all_findings,
        decision,
    }
}

// ----- Print scan JSON ----- //
// Expected behavior:
// - Print the scan report in a JSON format
fn print_json(report: &ScanReport) {
    println!("{}", serde_json::to_string_pretty(report).unwrap());
}

// ----- Print scan human ----- //
// Expected behavior:
// - Print the scan report in a human-readable format
fn print_human(report: &ScanReport) {
    println!("Decision: {:?}\n", report.decision);

    for t in &report.sections {
        println!("Section: {}", t.original);
        if let Some(idna) = &t.idna {
            println!("  IDNA : {}", idna);
        }
        if t.original != t.nfkc {
            println!("  NFKC : {}", t.nfkc);
        }
        if t.original != t.skeleton {
            println!("  Skel : {}", t.skeleton);
        }
        println!();
    }

    if report.findings.is_empty() {
        println!("Findings: none");
    } else {
        println!("Findings:");
        for f in &report.findings {
            println!("- [{:?}] {}: {}", f.level, f.kind, f.detail);
        }
    }
}

// ----- Main ----- //
// Expected behavior:
// - Print the scan report in a JSON format

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Scan { text, human } => {
            let report = scan_sections(&[text]);

            if human {
                print_human(&report);
            } else {
                print_json(&report);
            }

            ExitCode::SUCCESS
        }

        Cmd::Run {
            allow,
            human,
            command,
        } => {
            let report = scan_sections(&command);

            if human {
                print_human(&report);
            } else {
                print_json(&report);
            }

            if matches!(report.decision, Decision::Deny) && !allow {
                eprintln!("Execution blocked. Re-run with --allow to override.");
                return ExitCode::from(3);
            }

            if matches!(report.decision, Decision::Warn) && !allow {
                eprint!("Warning: Please confirm execution. (y/n): ");
                io::stdout().flush().unwrap();
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                if input.trim() != "y".to_lowercase() {
                    return ExitCode::from(2);
                }
            }

            let prog = &command[0];
            let args = &command[1..];

            match Command::new(prog).args(args).status() {
                Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
                Err(e) => {
                    eprintln!("Failed to execute {}: {}", prog, e);
                    ExitCode::from(1)
                }
            }
        }
    }
}
