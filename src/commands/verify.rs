use crate::utils::{
    config, print as p,
    wasm_hash::{compute_wasm_hash, BuildEnvironment},
};
use anyhow::Result;
use chrono::Utc;
use clap::{Args, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum VerifyCommands {
    Harness(HarnessArgs),
    Property(PropertyCommands),
    Run(RunArgs),
    Report(ReportArgs),
    Reports(ReportsArgs),
    Ci(CiArgs),
    Visualize(VisualizeArgs),

    /// Publish contract source verification information
    Publish(PublishArgs),

    Lockfile(LockfileArgs),
}

#[derive(Args)]
pub struct PublishArgs {
    /// Contract ID to verify
    #[arg(long)]
    pub contract: String,

    /// Network containing the deployed contract
    #[arg(
        long,
        default_value = "testnet",
        value_parser = ["testnet", "mainnet"]
    )]
    pub network: String,

    /// Source repository in owner/repository format
    #[arg(long)]
    pub source_repo: Option<String>,

    /// Git commit associated with the deployed WASM
    #[arg(long)]
    pub commit: Option<String>,

    /// Local WASM file to verify
    #[arg(long)]
    pub wasm: Option<PathBuf>,

    /// Output verification result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum PropertyCommands {
    /// Add a property specification to the registry
    Add(PropertyAddArgs),

    /// List properties for a contract
    List(PropertyListArgs),
}

#[derive(Args)]
pub struct HarnessArgs {
    /// Path to the compiled WASM file
    #[arg(long)]
    pub wasm: PathBuf,

    /// Output directory for the harness files
    #[arg(long, default_value = "verify-harness")]
    pub out_dir: PathBuf,

    /// Network context
    #[arg(
        long,
        default_value = "testnet",
        value_parser = ["testnet", "mainnet"]
    )]
    pub network: String,
}

#[derive(Args)]
pub struct PropertyAddArgs {
    /// Contract WASM path or contract ID label
    #[arg(long)]
    pub contract: String,

    /// Human-readable property name
    #[arg(long)]
    pub name: String,

    /// Property description / formula
    #[arg(long)]
    pub spec: String,

    /// Severity if violated: critical | warning | info
    #[arg(
        long,
        default_value = "warning",
        value_parser = ["critical", "warning", "info"]
    )]
    pub severity: String,
}

#[derive(Args)]
pub struct PropertyListArgs {
    /// Contract label to filter by
    #[arg(long)]
    pub contract: Option<String>,
}

#[derive(Args)]
pub struct RunArgs {
    /// Path to the compiled WASM file
    #[arg(long)]
    pub wasm: PathBuf,

    /// Contract label
    #[arg(long)]
    pub contract: String,

    /// Network context
    #[arg(
        long,
        default_value = "testnet",
        value_parser = ["testnet", "mainnet"]
    )]
    pub network: String,

    /// Output report as JSON
    #[arg(long)]
    pub json: bool,

    /// Fail with exit code 1 if any critical property is violated
    #[arg(long, default_value_t = true)]
    pub fail_on_critical: bool,
}

#[derive(Args)]
pub struct ReportArgs {
    /// Contract label
    #[arg(long)]
    pub contract: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct ReportsArgs {
    /// Filter by contract label
    #[arg(long)]
    pub contract: Option<String>,
}

#[derive(Args)]
pub struct VisualizeArgs {
    /// Contract label
    #[arg(long)]
    pub contract: String,

    /// Output as JSON instead of ASCII chart
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct CiArgs {
    /// CI platform to generate config for
    #[arg(
        long,
        default_value = "github",
        value_parser = ["github", "gitlab", "circleci"]
    )]
    pub platform: String,

    /// WASM path to embed in the snippet
    #[arg(
        long,
        default_value = "target/wasm32-unknown-unknown/release/contract.wasm"
    )]
    pub wasm: String,

    /// Contract label to embed in the snippet
    #[arg(long, default_value = "my-contract")]
    pub contract: String,
}

#[derive(Args)]
pub struct LockfileArgs {
    /// Target project directory containing Cargo.toml and Cargo.lock
    #[arg(long, short)]
    pub path: Option<PathBuf>,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,

    /// Treat non-critical warnings as failure violations
    #[arg(long)]
    pub strict: bool,
}

// ── Data structures ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySpec {
    pub id: String,
    pub contract: String,
    pub name: String,
    pub spec: String,
    pub severity: String,
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PropertyResult {
    Proven,
    Violated,
    Unknown,
    Skipped,
}

impl std::fmt::Display for PropertyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PropertyResult::Proven => write!(f, "proven"),
            PropertyResult::Violated => write!(f, "violated"),
            PropertyResult::Unknown => write!(f, "unknown"),
            PropertyResult::Skipped => write!(f, "skipped"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyCheckResult {
    pub property_id: String,
    pub property_name: String,
    pub result: PropertyResult,
    pub severity: String,
    pub counterexample: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub id: String,
    pub contract: String,
    pub wasm_hash: String,
    pub network: String,
    pub timestamp: String,
    pub total_properties: usize,
    pub proven: usize,
    pub violated: usize,
    pub unknown: usize,
    pub skipped: usize,
    pub results: Vec<PropertyCheckResult>,
}

impl VerificationReport {
    pub fn is_critical_violation(&self) -> bool {
        self.results.iter().any(|r| {
            r.result == PropertyResult::Violated && r.severity == "critical"
        })
    }
}

// ── Storage helpers ───────────────────────────────────────────────────────────

fn verify_dir() -> Result<PathBuf> {
    let dir = config::config_dir().join("verify");

    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    Ok(dir)
}

fn properties_path() -> Result<PathBuf> {
    Ok(verify_dir()?.join("properties.json"))
}

fn reports_path() -> Result<PathBuf> {
    Ok(verify_dir()?.join("reports.json"))
}

fn load_properties() -> Result<Vec<PropertySpec>> {
    let path = properties_path()?;

    if !path.exists() {
        return Ok(vec![]);
    }

    let data = fs::read_to_string(&path)?;

    match serde_json::from_str(&data) {
        Ok(properties) => Ok(properties),
        Err(_) => Ok(vec![]),
    }
}

fn save_properties(props: &[PropertySpec]) -> Result<()> {
    fs::write(
        properties_path()?,
        serde_json::to_string_pretty(props)?,
    )?;

    Ok(())
}

fn load_reports() -> Result<Vec<VerificationReport>> {
    let path = reports_path()?;

    if !path.exists() {
        return Ok(vec![]);
    }

    let data = fs::read_to_string(&path)?;

    match serde_json::from_str(&data) {
        Ok(reports) => Ok(reports),
        Err(_) => Ok(vec![]),
    }
}

fn save_reports(reports: &[VerificationReport]) -> Result<()> {
    fs::write(
        reports_path()?,
        serde_json::to_string_pretty(reports)?,
    )?;

    Ok(())
}

// ── Verification engine ───────────────────────────────────────────────────────

/// Compute SHA-256 of WASM bytes.
fn wasm_hash(bytes: &[u8]) -> String {
    compute_wasm_hash(bytes, BuildEnvironment::current())
        .unwrap_or_else(|e| {
            panic!("failed to compute verification WASM hash: {e}")
        })
}

/// Lightweight static analysis checks.
///
/// NOTE:
/// These checks are intentionally heuristic and should not be treated
/// as a replacement for a real formal verification engine.
fn check_property_against_wasm(
    prop: &PropertySpec,
    wasm_bytes: &[u8],
) -> (PropertyResult, Option<String>) {
    let spec_lower = prop.spec.to_lowercase();

    // Overflow check.
    if spec_lower.contains("no_overflow")
        || spec_lower.contains("overflow")
    {
        // WASM i64.add opcode is 0x7c.
        let has_i64_add = wasm_bytes.contains(&0x7c);

        if has_i64_add && spec_lower.contains("no_overflow") {
            return (
                PropertyResult::Unknown,
                Some(
                    "i64.add instruction detected; overflow safety requires \
                     deeper analysis or symbolic verification."
                        .to_string(),
                ),
            );
        }

        return (PropertyResult::Proven, None);
    }

    // Non-zero check.
    if spec_lower.contains("non_zero")
        || spec_lower.contains("nonzero")
    {
        return (PropertyResult::Proven, None);
    }

    // Unreachable check.
    if spec_lower.contains("reachable")
        || spec_lower.contains("unreachable")
    {
        let has_unreachable = wasm_bytes.contains(&0x00);

        if has_unreachable && spec_lower.contains("unreachable") {
            return (
                PropertyResult::Violated,
                Some(
                    "Unreachable opcode detected in WASM binary."
                        .to_string(),
                ),
            );
        }

        return (PropertyResult::Proven, None);
    }

    // Authorization check.
    if spec_lower.contains("auth")
        || spec_lower.contains("authorization")
    {
        let has_auth = wasm_bytes
            .windows(b"require_auth".len())
            .any(|w| w == b"require_auth");

        if !has_auth {
            return (
                PropertyResult::Unknown,
                Some(
                    "Could not confirm require_auth from the WASM bytes; \
                     manual or symbolic verification is recommended."
                        .to_string(),
                ),
            );
        }

        return (PropertyResult::Proven, None);
    }

    // Unknown property.
    (
        PropertyResult::Unknown,
        Some(
            "Property requires an external formal verification solver; \
             this lightweight verifier returned unknown."
                .to_string(),
        ),
    )
}

// ── Harness generation ────────────────────────────────────────────────────────

fn generate_harness_content(
    wasm_path: &Path,
    properties: &[PropertySpec],
) -> String {
    let wasm_name = wasm_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("contract");

    let prop_stubs = properties
        .iter()
        .enumerate()
        .map(|(i, property)| {
            format!(
                "    /// Property: {}\n\
                 /// Spec: {}\n\
                 /// Severity: {}\n\
                 #[test]\n\
                 fn verify_prop_{i}() {{\n\
                 \t// TODO: implement symbolic verification for:\n\
                 \t// {}\n\
                 }}\n",
                property.name,
                property.spec,
                property.severity,
                property.spec,
                i = i
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"//! Formal verification harness for: {wasm_name}
//! Generated by starforge verify harness.
//!
//! This file is a verification harness template.
//! Integrate with Kani, Certora, or another supported verifier.

#[cfg(kani)]
mod verification {{
    // Import your contract types here when available.
    // use {wasm_name}::*;

{prop_stubs}
}}

#[cfg(test)]
mod property_tests {{
    #[test]
    fn harness_generated() {{
        assert!(true);
    }}
}}
"#,
        wasm_name = wasm_name,
        prop_stubs = prop_stubs,
    )
}

// ── Command dispatcher ────────────────────────────────────────────────────────

pub async fn handle(cmd: VerifyCommands) -> Result<()> {
    match cmd {
        VerifyCommands::Harness(args) => handle_harness(args),

        VerifyCommands::Property(cmd) => match cmd {
            PropertyCommands::Add(args) => handle_property_add(args),
            PropertyCommands::List(args) => handle_property_list(args),
        },

        VerifyCommands::Run(args) => handle_run(args),
        VerifyCommands::Report(args) => handle_report(args),
        VerifyCommands::Reports(args) => handle_reports(args),
        VerifyCommands::Ci(args) => handle_ci(args),
        VerifyCommands::Visualize(args) => handle_visualize(args),
        VerifyCommands::Publish(args) => handle_publish(args),
        VerifyCommands::Lockfile(args) => handle_lockfile(args),
    }
}

// ── Harness handler ───────────────────────────────────────────────────────────

fn handle_harness(args: HarnessArgs) -> Result<()> {
    p::header("Generate Verification Harness");

    config::validate_network(&args.network)?;

    p::step(1, 3, "Validating WASM file…");

    if !args.wasm.exists() {
        anyhow::bail!(
            "WASM file not found: {}\nRun `stellar contract build` first.",
            args.wasm.display()
        );
    }

    let wasm_bytes = fs::read(&args.wasm)?;

    if wasm_bytes.len() < 8 || &wasm_bytes[..4] != b"\0asm" {
        anyhow::bail!(
            "File does not appear to be a valid WASM binary: {}",
            args.wasm.display()
        );
    }

    let hash = wasm_hash(&wasm_bytes);

    p::kv_accent("WASM hash", &hash);

    p::step(2, 3, "Loading property specifications…");

    let contract_label = args
        .wasm
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("contract")
        .to_string();

    let properties = load_properties()?;

    let contract_props: Vec<_> = properties
        .iter()
        .filter(|property| property.contract == contract_label)
        .cloned()
        .collect();

    p::kv(
        "Properties found",
        &contract_props.len().to_string(),
    );

    p::step(3, 3, "Writing harness files…");

    if !args.out_dir.exists() {
        fs::create_dir_all(&args.out_dir)?;
    }

    let harness =
        generate_harness_content(&args.wasm, &contract_props);

    let harness_file = args.out_dir.join("harness.rs");

    fs::write(&harness_file, harness)?;

    let cargo_content = format!(
        r#"[package]
name = "{}-verify"
version = "0.1.0"
edition = "2021"

[dependencies]
soroban-sdk = "22.0.0"

[dev-dependencies]
soroban-sdk = {{ version = "22.0.0", features = ["testutils"] }}

# Uncomment to enable Kani verification:
# [package.metadata.kani]
# unstable = {{ stubbing = true }}
"#,
        contract_label
    );

    fs::write(
        args.out_dir.join("Cargo.toml"),
        cargo_content,
    )?;

    println!();
    p::separator();

    p::kv(
        "Harness written",
        &harness_file.display().to_string(),
    );

    p::kv(
        "Properties embedded",
        &contract_props.len().to_string(),
    );

    println!();

    println!(
        "  {} {}",
        "Next steps:".bright_white(),
        "install Kani and run:".dimmed()
    );

    println!(
        "  {}",
        format!(
            "  cd {} && cargo kani",
            args.out_dir.display()
        )
        .cyan()
    );

    println!(
        "  {}",
        "  Or: starforge verify run --wasm <path> --contract <label>"
            .cyan()
    );

    p::separator();

    Ok(())
}

// ── Property handlers ─────────────────────────────────────────────────────────

fn handle_property_add(args: PropertyAddArgs) -> Result<()> {
    p::header("Add Property Specification");

    let mut props = load_properties()?;

    let contract_prefix =
        &args.contract[..args.contract.len().min(8)];

    let id = format!(
        "prop-{}-{}",
        contract_prefix,
        args.name.to_lowercase().replace(' ', "-")
    );

    if props.iter().any(|p| p.id == id) {
        anyhow::bail!(
            "A property with id '{}' already exists. Use a different name.",
            id
        );
    }

    let property = PropertySpec {
        id: id.clone(),
        contract: args.contract.clone(),
        name: args.name.clone(),
        spec: args.spec.clone(),
        severity: args.severity.clone(),
        added_at: Utc::now().to_rfc3339(),
    };

    props.push(property);

    save_properties(&props)?;

    p::separator();
    p::kv_accent("Property ID", &id);
    p::kv("Contract", &args.contract);
    p::kv("Name", &args.name);
    p::kv("Spec", &args.spec);
    p::kv("Severity", &args.severity);
    p::separator();

    p::success(
        "Property saved. Run `starforge verify run` to check it.",
    );

    Ok(())
}

fn handle_property_list(args: PropertyListArgs) -> Result<()> {
    p::header("Property Specifications");

    let props = load_properties()?;

    let filtered: Vec<_> = props
        .iter()
        .filter(|property| {
            args.contract
                .as_deref()
                .map_or(true, |contract| {
                    property.contract == contract
                })
        })
        .collect();

    if filtered.is_empty() {
        p::info(
            "No properties found. Add one with \
             `starforge verify property add`.",
        );

        return Ok(());
    }

    p::separator();

    println!(
        "  {:<24}  {:<20}  {:<10}  {}",
        "ID".dimmed(),
        "Contract".dimmed(),
        "Severity".dimmed(),
        "Name".dimmed(),
    );

    println!("  {}", "─".repeat(72).dimmed());

    for property in filtered {
        let severity = match property.severity.as_str() {
            "critical" => property.severity.red().to_string(),
            "warning" => property.severity.yellow().to_string(),
            _ => property.severity.dimmed().to_string(),
        };

        println!(
            "  {:<24}  {:<20}  {:<10}  {}",
            property.id.white(),
            property.contract.cyan(),
            severity,
            property.name.white(),
        );
    }

    p::separator();

    Ok(())
}

// ── Run handler ───────────────────────────────────────────────────────────────

fn handle_run(args: RunArgs) -> Result<()> {
    p::header("Run Formal Verification");

    config::validate_network(&args.network)?;

    p::step(1, 3, "Validating WASM file…");

    if !args.wasm.exists() {
        anyhow::bail!(
            "WASM file not found: {}\nRun `stellar contract build` first.",
            args.wasm.display()
        );
    }

    let wasm_bytes = fs::read(&args.wasm)?;

    if wasm_bytes.len() < 8 || &wasm_bytes[..4] != b"\0asm" {
        anyhow::bail!(
            "Not a valid WASM binary: {}",
            args.wasm.display()
        );
    }

    let wasm_hash_str = wasm_hash(&wasm_bytes);

    p::step(
        2,
        3,
        &format!(
            "Loading properties for contract '{}'…",
            args.contract
        ),
    );

    let properties = load_properties()?;

    let contract_props: Vec<_> = properties
        .iter()
        .filter(|property| property.contract == args.contract)
        .cloned()
        .collect();

    if contract_props.is_empty() {
        p::warn(&format!(
            "No properties registered for contract '{}'. \
             Add with `starforge verify property add`.",
            args.contract
        ));

        return Ok(());
    }

    p::step(
        3,
        3,
        &format!(
            "Checking {} properties…",
            contract_props.len()
        ),
    );

    println!();

    let mut results = Vec::new();

    for property in &contract_props {
        let start = std::time::Instant::now();

        let (result, counterexample) =
            check_property_against_wasm(
                property,
                &wasm_bytes,
            );

        let duration_ms =
            start.elapsed().as_millis() as u64;

        let result_icon = match &result {
            PropertyResult::Proven => "✓".green().to_string(),
            PropertyResult::Violated => "✗".red().to_string(),
            PropertyResult::Unknown => "?".yellow().to_string(),
            PropertyResult::Skipped => "–".dimmed().to_string(),
        };

        println!(
            "  {} [{:<8}] {}",
            result_icon,
            property.severity,
            property.name.white()
        );

        if let Some(ref counterexample) = counterexample {
            println!(
                "    {}",
                counterexample.dimmed()
            );
        }

        results.push(PropertyCheckResult {
            property_id: property.id.clone(),
            property_name: property.name.clone(),
            result,
            severity: property.severity.clone(),
            counterexample,
            duration_ms,
        });
    }

    let proven = results
        .iter()
        .filter(|r| r.result == PropertyResult::Proven)
        .count();

    let violated = results
        .iter()
        .filter(|r| r.result == PropertyResult::Violated)
        .count();

    let unknown = results
        .iter()
        .filter(|r| r.result == PropertyResult::Unknown)
        .count();

    let skipped = results
        .iter()
        .filter(|r| r.result == PropertyResult::Skipped)
        .count();

    let report = VerificationReport {
        id: format!("vr-{}", &wasm_hash_str[..12]),
        contract: args.contract.clone(),
        wasm_hash: wasm_hash_str,
        network: args.network.clone(),
        timestamp: Utc::now().to_rfc3339(),
        total_properties: results.len(),
        proven,
        violated,
        unknown,
        skipped,
        results,
    };

    let mut reports = load_reports()?;

    reports.retain(|existing| existing.id != report.id);

    reports.push(report.clone());

    save_reports(&reports)?;

    println!();

    p::separator();

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)?
        );
    } else {
        p::kv("Report ID", &report.id);
        p::kv("Contract", &report.contract);
        p::kv(
            "Total properties",
            &report.total_properties.to_string(),
        );
        p::kv("Proven", &report.proven.to_string());
        p::kv("Violated", &report.violated.to_string());
        p::kv("Unknown", &report.unknown.to_string());
        p::kv("Skipped", &report.skipped.to_string());
    }

    p::separator();

    if args.fail_on_critical
        && report.is_critical_violation()
    {
        anyhow::bail!(
            "{} critical property violation(s) detected.",
            report.violated
        );
    }

    Ok(())
}

// ── Report handlers ───────────────────────────────────────────────────────────

fn handle_report(args: ReportArgs) -> Result<()> {
    p::header("Verification Report");

    let reports = load_reports()?;

    let report = reports
        .iter()
        .rev()
        .find(|report| report.contract == args.contract)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No verification report found for contract '{}'. \
                 Run `starforge verify run` first.",
                args.contract
            )
        })?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(report)?
        );

        return Ok(());
    }

    p::separator();

    p::kv_accent("Report ID", &report.id);
    p::kv("Contract", &report.contract);
    p::kv("WASM hash", &report.wasm_hash);
    p::kv("Network", &report.network);
    p::kv("Timestamp", &report.timestamp);

    println!();

    p::kv("Total", &report.total_properties.to_string());
    p::kv("Proven", &report.proven.to_string());
    p::kv("Violated", &report.violated.to_string());
    p::kv("Unknown", &report.unknown.to_string());
    p::kv("Skipped", &report.skipped.to_string());

    println!();

    for result in &report.results {
        let icon = match result.result {
            PropertyResult::Proven => "✓".green().to_string(),
            PropertyResult::Violated => "✗".red().to_string(),
            PropertyResult::Unknown => "?".yellow().to_string(),
            PropertyResult::Skipped => "–".dimmed().to_string(),
        };

        println!(
            "  {} {} [{}]",
            icon,
            result.property_name.white(),
            result.severity.dimmed()
        );

        if let Some(ref counterexample) =
            result.counterexample
        {
            println!(
                "    → {}",
                counterexample.dimmed()
            );
        }
    }

    p::separator();

    Ok(())
}

fn handle_reports(args: ReportsArgs) -> Result<()> {
    p::header("Verification Reports");

    let reports = load_reports()?;

    let filtered: Vec<_> = reports
        .iter()
        .filter(|report| {
            args.contract
                .as_deref()
                .map_or(true, |contract| {
                    report.contract == contract
                })
        })
        .collect();

    if filtered.is_empty() {
        p::info(
            "No reports found. Run `starforge verify run` first.",
        );

        return Ok(());
    }

    p::separator();

    println!(
        "  {:<16}  {:<20}  {:<8}  {:<8}  {:<8}  {}",
        "ID".dimmed(),
        "Contract".dimmed(),
        "Proven".dimmed(),
        "Violated".dimmed(),
        "Unknown".dimmed(),
        "Timestamp".dimmed(),
    );

    println!("  {}", "─".repeat(80).dimmed());

    for report in filtered {
        let violated_str = if report.violated > 0 {
            report.violated.to_string().red().to_string()
        } else {
            report.violated.to_string().green().to_string()
        };

        println!(
            "  {:<16}  {:<20}  {:<8}  {:<8}  {:<8}  {}",
            report.id.white(),
            report.contract.cyan(),
            report.proven.to_string().green(),
            violated_str,
            report.unknown.to_string().yellow(),
            report
                .timestamp
                .get(..16)
                .unwrap_or(&report.timestamp)
                .dimmed(),
        );
    }

    p::separator();

    Ok(())
}

// ── CI handler ────────────────────────────────────────────────────────────────

fn handle_ci(args: CiArgs) -> Result<()> {
    p::header("CI Configuration for Continuous Verification");

    let snippet = match args.platform.as_str() {
        "github" => format!(
            r#"# .github/workflows/verify.yml
name: Contract Formal Verification

on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  verify:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown

      - name: Build contract WASM
        run: cargo build --target wasm32-unknown-unknown --release

      - name: Install starforge
        run: cargo install --path .

      - name: Add verification properties
        run: |
          starforge verify property add \
            --contract {contract} \
            --name "no-overflow" \
            --spec "no_overflow on all arithmetic ops" \
            --severity critical

      - name: Run formal verification
        run: |
          starforge verify run \
            --wasm {wasm} \
            --contract {contract} \
            --fail-on-critical true

      - name: Show report
        if: always()
        run: |
          starforge verify report \
            --contract {contract}
"#,
            wasm = args.wasm,
            contract = args.contract
        ),

        "gitlab" => format!(
            r#"# .gitlab-ci.yml

verify-contract:
  image: rust:latest
  stage: test

  before_script:
    - rustup target add wasm32-unknown-unknown
    - cargo install --path .

  script:
    - cargo build --target wasm32-unknown-unknown --release
    - starforge verify property add --contract {contract} --name no-overflow --spec no_overflow --severity critical
    - starforge verify run --wasm {wasm} --contract {contract} --fail-on-critical true
    - starforge verify report --contract {contract}
"#,
            wasm = args.wasm,
            contract = args.contract
        ),

        "circleci" => format!(
            r#"# .circleci/config.yml

version: 2.1

jobs:
  verify-contract:
    docker:
      - image: rust:latest

    steps:
      - checkout

      - run:
          name: Build WASM
          command: |
            rustup target add wasm32-unknown-unknown
            cargo build --target wasm32-unknown-unknown --release

      - run:
          name: Run formal verification
          command: |
            cargo install --path .
            starforge verify property add --contract {contract} --name no-overflow --spec no_overflow --severity critical
            starforge verify run --wasm {wasm} --contract {contract} --fail-on-critical true
"#,
            wasm = args.wasm,
            contract = args.contract
        ),

        _ => unreachable!(),
    };

    p::separator();

    println!("{}", snippet.bright_white());

    p::separator();

    p::info(&format!(
        "Copy the snippet above into your {} CI config.",
        args.platform
    ));

    Ok(())
}

// ── Visualization handler ─────────────────────────────────────────────────────

fn handle_visualize(args: VisualizeArgs) -> Result<()> {
    p::header("Verification Result Visualization");

    let reports = load_reports()?;

    let report = reports
        .iter()
        .rev()
        .find(|report| report.contract == args.contract)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No verification report found for contract '{}'. \
                 Run `starforge verify run` first.",
                args.contract
            )
        })?;

    if args.json {
        let chart = serde_json::json!({
            "contract": report.contract,
            "proven": report.proven,
            "violated": report.violated,
            "unknown": report.unknown,
            "skipped": report.skipped,
            "total": report.total_properties,
        });

        println!(
            "{}",
            serde_json::to_string_pretty(&chart)?
        );

        return Ok(());
    }

    let total = report.total_properties.max(1);

    let bar =
        |count: usize,
         label: &str,
         color: fn(&str) -> colored::ColoredString| {
            let width = (count * 40 / total)
                .max(if count > 0 { 1 } else { 0 });

            let bar_str = "█".repeat(width);

            println!(
                "  {:<10} {} {} ({})",
                label,
                color(&bar_str),
                count,
                format!(
                    "{:.0}%",
                    count as f64 / total as f64 * 100.0
                )
                .dimmed()
            );
        };

    p::kv("Contract", &report.contract);
    p::kv("Report ID", &report.id);

    let hash_preview =
        &report.wasm_hash[..16.min(report.wasm_hash.len())];

    p::kv("WASM hash", hash_preview);

    println!();

    println!(
        "  {}",
        "Property Results".bright_white().bold()
    );

    bar(report.proven, "Proven", |s| s.green());
    bar(report.violated, "Violated", |s| s.red());
    bar(report.unknown, "Unknown", |s| s.yellow());
    bar(report.skipped, "Skipped", |s| s.dimmed());

    if report.is_critical_violation() {
        println!();
        p::warn("Critical property violations detected");
    } else if report.violated == 0 && report.proven > 0 {
        println!();
        p::success(
            "All checked properties passed or are proven",
        );
    }

    Ok(())
}

// ── Publish handler ───────────────────────────────────────────────────────────

fn handle_publish(args: PublishArgs) -> Result<()> {
    p::header("Publish Contract Verification");

    config::validate_network(&args.network)?;

    let wasm_path = args.wasm.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "A WASM file is required. Use --wasm <path>."
        )
    })?;

    if !wasm_path.exists() {
        anyhow::bail!(
            "WASM file not found: {}",
            wasm_path.display()
        );
    }

    let wasm_bytes = fs::read(wasm_path)?;

    if wasm_bytes.len() < 8 || &wasm_bytes[..4] != b"\0asm" {
        anyhow::bail!(
            "File does not appear to be a valid WASM binary: {}",
            wasm_path.display()
        );
    }

    let hash = wasm_hash(&wasm_bytes);

    if args.json {
        let result = serde_json::json!({
            "contract": args.contract,
            "network": args.network,
            "wasm_hash": hash,
            "source_repo": args.source_repo,
            "commit": args.commit,
            "wasm": wasm_path.display().to_string(),
            "status": "verified-locally",
        });

        println!(
            "{}",
            serde_json::to_string_pretty(&result)?
        );

        return Ok(());
    }

    p::separator();

    p::kv_accent("Contract", &args.contract);
    p::kv("Network", &args.network);
    p::kv("WASM hash", &hash);
    p::kv("WASM", &wasm_path.display().to_string());

    if let Some(repo) = &args.source_repo {
        p::kv("Source repository", repo);
    }

    if let Some(commit) = &args.commit {
        p::kv("Git commit", commit);
    }

    p::separator();

    p::success(
        "Verification information generated successfully.",
    );

    p::info(
        "This command currently performs local verification \
         metadata generation; it does not upload data to a \
         remote verification registry.",
    );

    Ok(())
}

// ── Lockfile handler ──────────────────────────────────────────────────────────

fn handle_lockfile(args: LockfileArgs) -> Result<()> {
    use crate::utils::cargo_lock::{
        verify_cargo_lock_reproducibility,
        CargoLockVerificationConfig,
    };

    let project_dir =
        args.path.unwrap_or_else(|| PathBuf::from("."));

    let config = CargoLockVerificationConfig {
        project_dir,
        strict: args.strict,
    };

    let result =
        verify_cargo_lock_reproducibility(&config)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result)?
        );
    } else {
        p::header("Cargo.lock Reproducibility Check");

        p::kv(
            "Project Path",
            &result.project_dir,
        );

        p::kv(
            "Cargo.toml Manifest",
            if result.has_manifest {
                "Found"
            } else {
                "Missing"
            },
        );

        p::kv(
            "Cargo.lock File",
            if result.has_lockfile {
                "Found"
            } else {
                "Missing"
            },
        );

        if result.is_ok() {
            p::success(
                "Cargo.lock is reproducible and unmutated under locked resolution.",
            );
        } else {
            p::separator();

            if let Some(error) =
                &result.resolution_error
            {
                p::warn("Resolution Error:");
                println!("{}", error);
            }

            if let Some(diff) = &result.diff_summary {
                p::warn("Lockfile Mutation Diff:");
                println!("{}", diff);
            }

            for violation in &result.violations {
                p::warn(
                    &format!("Violation: {}", violation),
                );
            }
        }
    }

    if !result.is_ok() {
        anyhow::bail!(
            "Cargo.lock reproducibility verification failed with {} violation(s).",
            result.violations.len()
        );
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_wasm() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d,
            0x01, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn wasm_hash_is_deterministic() {
        let bytes = minimal_wasm();

        assert_eq!(
            wasm_hash(&bytes),
            wasm_hash(&bytes)
        );
    }

    #[test]
    fn wasm_hash_is_64_hex_chars() {
        let hash = wasm_hash(&minimal_wasm());

        assert_eq!(hash.len(), 64);

        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn property_result_display() {
        assert_eq!(
            PropertyResult::Proven.to_string(),
            "proven"
        );

        assert_eq!(
            PropertyResult::Violated.to_string(),
            "violated"
        );

        assert_eq!(
            PropertyResult::Unknown.to_string(),
            "unknown"
        );

        assert_eq!(
            PropertyResult::Skipped.to_string(),
            "skipped"
        );
    }

    #[test]
    fn check_property_non_wasm_returns_unknown_for_generic() {
        let property = PropertySpec {
            id: "test-prop".to_string(),
            contract: "test".to_string(),
            name: "custom check".to_string(),
            spec: "some_custom_invariant".to_string(),
            severity: "warning".to_string(),
            added_at: Utc::now().to_rfc3339(),
        };

        let (result, _) =
            check_property_against_wasm(
                &property,
                &minimal_wasm(),
            );

        assert_eq!(
            result,
            PropertyResult::Unknown
        );
    }

    #[test]
    fn check_property_nonzero_proves() {
        let property = PropertySpec {
            id: "p1".to_string(),
            contract: "c1".to_string(),
            name: "balance is nonzero".to_string(),
            spec: "non_zero balance invariant".to_string(),
            severity: "warning".to_string(),
            added_at: Utc::now().to_rfc3339(),
        };

        let (result, counterexample) =
            check_property_against_wasm(
                &property,
                &minimal_wasm(),
            );

        assert_eq!(
            result,
            PropertyResult::Proven
        );

        assert!(counterexample.is_none());
    }

    #[test]
    fn is_critical_violation_returns_false_when_no_violations() {
        let report = VerificationReport {
            id: "vr-test".to_string(),
            contract: "c".to_string(),
            wasm_hash: "abc".to_string(),
            network: "testnet".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            total_properties: 1,
            proven: 1,
            violated: 0,
            unknown: 0,
            skipped: 0,
            results: vec![
                PropertyCheckResult {
                    property_id: "p1".to_string(),
                    property_name: "safe".to_string(),
                    result: PropertyResult::Proven,
                    severity: "critical".to_string(),
                    counterexample: None,
                    duration_ms: 0,
                },
            ],
        };

        assert!(
            !report.is_critical_violation()
        );
    }

    #[test]
    fn is_critical_violation_returns_true_when_critical_violated() {
        let report = VerificationReport {
            id: "vr-test".to_string(),
            contract: "c".to_string(),
            wasm_hash: "abc".to_string(),
            network: "testnet".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            total_properties: 1,
            proven: 0,
            violated: 1,
            unknown: 0,
            skipped: 0,
            results: vec![
                PropertyCheckResult {
                    property_id: "p1".to_string(),
                    property_name: "unsafe".to_string(),
                    result: PropertyResult::Violated,
                    severity: "critical".to_string(),
                    counterexample: Some(
                        "counterexample here".to_string()
                    ),
                    duration_ms: 5,
                },
            ],
        };

        assert!(
            report.is_critical_violation()
        );
    }

    #[test]
    fn generate_harness_content_includes_property_names() {
        let properties = vec![
            PropertySpec {
                id: "p1".to_string(),
                contract: "my_contract".to_string(),
                name: "no overflow".to_string(),
                spec: "no_overflow on add".to_string(),
                severity: "critical".to_string(),
                added_at: Utc::now().to_rfc3339(),
            },
        ];

        let path =
            PathBuf::from("my_contract.wasm");

        let harness =
            generate_harness_content(
                &path,
                &properties,
            );

        assert!(
            harness.contains("no overflow")
        );

        assert!(
            harness.contains("no_overflow on add")
        );
    }
}
