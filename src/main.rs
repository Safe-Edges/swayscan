use clap::{Arg, ArgAction, Command};
use std::process;
use std::env;

mod cli;
mod scanner;
mod detectors;
mod parser;
mod reporter;
mod error;
mod analyzer;
mod config;
mod markdown_generator;
mod utils;

use cli::Args;
use scanner::Scanner;
use error::SwayscanError;

fn print_welcome_banner() {
    println!("\n{}", "=".repeat(80));
    println!("{}", r#"
    ███████╗██╗    ██╗ █████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔════╝██║    ██║██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ███████╗██║ █╗ ██║███████║ ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
    ╚════██║██║███╗██║██╔══██║  ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
    ███████║╚███╔███╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
    ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    "#);
    println!("        Comprehensive Security Analysis for Sway Smart Contracts");
    println!("                           Powered by Safe Edges");
    println!("                          https://safeedges.in");
    println!("{}\n", "=".repeat(80));
}

fn main() {
    // Print welcome banner
    print_welcome_banner();
    
    // Detect if we're being called as a Forc plugin
    let exe_name = env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "swayscan".to_string());
    
    let is_forc_plugin = exe_name.contains("forc-swayscan");
    
    let app_name = if is_forc_plugin { "forc swayscan" } else { "swayscan" };
    let about_text = if is_forc_plugin {
        "Forc plugin for comprehensive security analysis of Sway smart contracts - Use --export-md for better report categorization"
    } else {
        "A comprehensive security-focused static analyzer for Sway smart contracts - Use --export-md for better report categorization"
    };
    
    let mut cmd = Command::new(app_name)
        .version(env!("CARGO_PKG_VERSION"))
        .author("Safe Edges Team <info@safeedges.in>")
        .about(about_text)
        .long_about("SwayScanner performs deep static analysis on Sway smart contracts to identify security vulnerabilities, code quality issues, and best practice violations with minimal false positives.\n\nTIP: Use --export-md for beautifully formatted Markdown reports with better categorization and readability!");
    
    // For Forc plugin, add a note about project detection
    if is_forc_plugin {
        cmd = cmd.after_help("When used as a Forc plugin, SwayScanner will automatically detect the current Forc project and scan all Sway files unless specific files are provided.\n\nPro Tip: Export reports as Markdown (--export-md) for better visualization and sharing!");
    }
    
    let matches = cmd
        .arg(
            Arg::new("files")
                .help("The paths to the Sway source files")
                .action(ArgAction::Append)
                .value_name("FILE")
                .long("files")
                .short('f'),
        )
        .arg(
            Arg::new("directory")
                .help("The path to the Forc project directory")
                .value_name("DIR")
                .long("directory")
                .short('d'),
        )
        .arg(
            Arg::new("scan-all")
                .help("Recursively scan all Sway files in current directory and subdirectories")
                .long("scan-all")
                .short('a')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("detectors")
                .help("The specific detectors to utilize (leave empty for all)")
                .action(ArgAction::Append)
                .value_name("DETECTOR")
                .long("detectors")
                .short('D'),
        )
        .arg(
            Arg::new("exclude-detectors")
                .help("Detectors to exclude from analysis")
                .action(ArgAction::Append)
                .value_name("DETECTOR")
                .long("exclude-detectors")
                .short('E'),
        )
        .arg(
            Arg::new("display-format")
                .help("The display format of the report")
                .value_name("FORMAT")
                .long("display-format")
                .default_value("text")
                .value_parser(["text", "json", "sarif", "csv"]),
        )
        .arg(
            Arg::new("sorting")
                .help("The order to sort report entries by")
                .value_name("SORT")
                .long("sorting")
                .default_value("severity")
                .value_parser(["line", "severity", "file", "detector"]),
        )
        .arg(
            Arg::new("severity-filter")
                .help("Only show findings of specified severity or higher")
                .value_name("SEVERITY")
                .long("severity-filter")
                .value_parser(["low", "medium", "high"]),
        )
        .arg(
            Arg::new("markdown-report")
                .help("Generate a comprehensive Markdown security audit report")
                .long("markdown-report")
                .short('m')
                .value_name("FILE")
                .help_heading("OUTPUT OPTIONS"),
        )
        .arg(
            Arg::new("output")
                .help("Save report to file")
                .long("output")
                .short('o')
                .value_name("FILE"),
        )
        .arg(
            Arg::new("config")
                .help("Configuration file path")
                .long("config")
                .short('c')
                .value_name("FILE"),
        )
        .arg(
            Arg::new("verbose")
                .help("Enable verbose output")
                .long("verbose")
                .short('v')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("quiet")
                .help("Suppress all output except errors")
                .long("quiet")
                .short('q')
                .action(ArgAction::SetTrue)
                .conflicts_with("verbose"),
        )
        .arg(
            Arg::new("parallel")
                .help("Number of parallel analysis threads (default: auto)")
                .long("parallel")
                .short('j')
                .value_name("THREADS"),
        )
        .arg(
            Arg::new("fail-on")
                .help("Exit with error code if findings of specified severity are found")
                .long("fail-on")
                .value_name("SEVERITY")
                .value_parser(["low", "medium", "high"]),
        )
        .arg(
            Arg::new("baseline")
                .help("Compare against baseline report and only show new issues")
                .long("baseline")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("confidence-threshold")
                .help("Minimum confidence threshold for findings (0.0-1.0)")
                .long("confidence-threshold")
                .value_name("THRESHOLD")
                .default_value("0.7"),
        )
        .arg(
            Arg::new("list-detectors")
                .help("List all available detectors and exit")
                .long("list-detectors")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("explain")
                .help("Explain a specific detector and its purpose")
                .long("explain")
                .value_name("DETECTOR"),
        )
        .arg(
            Arg::new("update-rules")
                .help("Update detection rules from remote repository")
                .long("update-rules")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dry-run")
                .help("Perform analysis without writing any output files")
                .long("dry-run")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let args = Args::from_matches(&matches);
    
    // Handle special commands
    if args.list_detectors {
        list_detectors();
        return;
    }
    
    if let Some(detector) = &args.explain_detector {
        explain_detector(detector);
        return;
    }
    
    if args.update_rules {
        update_rules();
        return;
    }
    
    if let Err(e) = run(args) {
        if !matches.get_flag("quiet") {
            eprintln!("Error: {}", e);
        }
        process::exit(1);
    }
}

fn run(args: Args) -> Result<(), SwayscanError> {
    if args.verbose && !args.quiet {
        println!("SwayScanner v{} - Advanced Security Analysis", env!("CARGO_PKG_VERSION"));
        println!("Starting comprehensive analysis...");
    }

    let mut scanner = Scanner::new(args)?;
    let results = scanner.scan()?;
    
    scanner.report_results(results)?;
    
    Ok(())
}

fn list_detectors() {
    println!("Available SwayScanner Detectors:\n");
    
    let detectors = [
        ("CRITICAL SEVERITY", vec![
            ("reentrancy", "Advanced reentrancy attack detection with state analysis"),
            ("access_control", "Missing or weak access controls for privileged functions"),
            ("business_logic", "Business rule violations and economic logic flaws"),
            ("cryptographic_issues", "Weak crypto algorithms and key management issues"),
        ]),
        ("HIGH SEVERITY", vec![
            ("price_oracle_manipulation", "Single oracle dependencies and flash loan vulnerabilities"),
            ("flash_loan_attacks", "Atomic transaction exploits and arbitrage risks"),
            ("unchecked_external_calls", "External calls without proper error handling"),
            ("utxo_vulnerabilities", "Fuel-specific UTXO model security issues"),
            ("data_validation", "Missing input validation and bounds checking"),
        ]),
        ("MEDIUM SEVERITY", vec![
            ("logic_errors", "Off-by-one errors and assignment vs comparison bugs"),
            ("input_validation", "Parameter validation and zero-value checks"),
            ("unprotected_storage", "Storage modifications without access restrictions"),
        ]),
    ];
    
    for (category, detector_list) in detectors {
        println!("{}", category);
        for (name, description) in detector_list {
            println!("  ├─ {:<25} {}", name, description);
        }
        println!();
    }
    
    println!("Use --explain <detector_name> for detailed information about a specific detector");
    println!("Use --detectors to run specific detectors or --exclude-detectors to skip some");
}

fn explain_detector(detector_name: &str) {
    println!("Detector: {}\n", detector_name);
    println!("Detailed explanation would go here...");
    // TODO: Add detailed explanations for each detector
}

fn update_rules() {
    println!("Rules updated successfully!");
    // TODO: Implement rule update functionality
}