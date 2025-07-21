use clap::{Arg, ArgAction, ArgMatches, Command};
use std::path::{Path, PathBuf};
use crate::detectors::Severity;

#[derive(Debug, Clone)]
pub struct Args {
    pub files: Vec<PathBuf>,
    pub directory: Option<PathBuf>,
    pub scan_all: bool,
    pub detectors: Vec<String>,
    pub exclude_detectors: Vec<String>,
    pub display_format: OutputFormat,
    pub sorting: SortOrder,
    pub severity_filter: Option<SeverityLevel>,
    pub markdown_report: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub config: Option<PathBuf>,
    pub verbose: bool,
    pub quiet: bool,
    pub parallel: Option<usize>,
    pub fail_on: Option<SeverityLevel>,
    pub baseline: Option<PathBuf>,
    pub confidence_threshold: f64,
    pub list_detectors: bool,
    pub explain_detector: Option<String>,
    pub update_rules: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Csv,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SortOrder {
    Line,
    Severity,
    File,
    Detector,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
}

impl Args {
    pub fn from_matches(matches: &ArgMatches) -> Self {
        let mut files: Vec<PathBuf> = matches
            .get_many::<String>("files")
            .map(|files| files.map(PathBuf::from).collect())
            .unwrap_or_default();

        let mut directory = matches
            .get_one::<String>("directory")
            .map(PathBuf::from);

        let scan_all = matches.get_flag("scan-all");

        // Auto-detect Forc project if no specific files/directory provided and we're likely a plugin
        let exe_name = std::env::current_exe()
            .ok()
            .and_then(|path| path.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "swayscan".to_string());
        
        let is_forc_plugin = exe_name.contains("forc-swayscan");
        
        if is_forc_plugin && files.is_empty() && directory.is_none() && !scan_all {
            // Look for Forc.toml in current directory or parents
            let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            
            if let Some(forc_project_root) = find_forc_project_root(&current_dir) {
                directory = Some(forc_project_root);
                if matches.get_flag("verbose") {
                    eprintln!("Auto-detected Forc project at: {}", directory.as_ref().unwrap().display());
                }
            } else {
                // Fallback to scanning current directory
                files.push(current_dir);
                if matches.get_flag("verbose") {
                    eprintln!("No Forc.toml found, scanning current directory");
                }
            }
        }

        let detectors = matches
            .get_many::<String>("detectors")
            .map(|detectors| detectors.cloned().collect())
            .unwrap_or_default();

        let exclude_detectors = matches
            .get_many::<String>("exclude-detectors")
            .map(|detectors| detectors.cloned().collect())
            .unwrap_or_default();

        let display_format = match matches.get_one::<String>("display-format").unwrap().as_str() {
            "json" => OutputFormat::Json,
            "sarif" => OutputFormat::Sarif,
            "csv" => OutputFormat::Csv,
            _ => OutputFormat::Text,
        };

        let sorting = match matches.get_one::<String>("sorting").unwrap().as_str() {
            "line" => SortOrder::Line,
            "file" => SortOrder::File,
            "detector" => SortOrder::Detector,
            _ => SortOrder::Severity,
        };

        let severity_filter = matches
            .get_one::<String>("severity-filter")
            .map(|s| match s.as_str() {
                "high" => SeverityLevel::High,
                "medium" => SeverityLevel::Medium,
                _ => SeverityLevel::Low,
            });

        let markdown_report = matches
            .get_one::<String>("markdown-report")
            .map(PathBuf::from);

        let output = matches
            .get_one::<String>("output")
            .map(PathBuf::from);

        let config = matches
            .get_one::<String>("config")
            .map(PathBuf::from);

        let verbose = matches.get_flag("verbose");
        let quiet = matches.get_flag("quiet");

        let parallel = matches
            .get_one::<String>("parallel")
            .and_then(|s| s.parse().ok());

        let fail_on = matches
            .get_one::<String>("fail-on")
            .map(|s| match s.as_str() {
                "high" => SeverityLevel::High,
                "medium" => SeverityLevel::Medium,
                _ => SeverityLevel::Low,
            });

        let baseline = matches
            .get_one::<String>("baseline")
            .map(PathBuf::from);

        let confidence_threshold = matches
            .get_one::<String>("confidence-threshold")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.7);

        let list_detectors = matches.get_flag("list-detectors");

        let explain_detector = matches
            .get_one::<String>("explain")
            .map(|s| s.to_string());

        let update_rules = matches.get_flag("update-rules");
        let dry_run = matches.get_flag("dry-run");

        Args {
            files,
            directory,
            scan_all,
            detectors,
            exclude_detectors,
            display_format,
            sorting,
            severity_filter,
            markdown_report,
            output,
            config,
            verbose,
            quiet,
            parallel,
            fail_on,
            baseline,
            confidence_threshold,
            list_detectors,
            explain_detector,
            update_rules,
            dry_run,
        }
    }

    pub fn has_input(&self) -> bool {
        !self.files.is_empty() || self.directory.is_some() || self.scan_all
    }

    pub fn should_run_all_detectors(&self) -> bool {
        self.detectors.is_empty() && self.exclude_detectors.is_empty()
    }

    pub fn get_thread_count(&self) -> usize {
        self.parallel.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
    }

    pub fn should_generate_markdown(&self) -> bool {
        self.markdown_report.is_some()
    }

    pub fn meets_confidence_threshold(&self, confidence: f64) -> bool {
        confidence >= self.confidence_threshold
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
            OutputFormat::Csv => write!(f, "csv"),
        }
    }
}

impl std::fmt::Display for SortOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortOrder::Line => write!(f, "line"),
            SortOrder::Severity => write!(f, "severity"),
            SortOrder::File => write!(f, "file"),
            SortOrder::Detector => write!(f, "detector"),
        }
    }
}

impl std::fmt::Display for SeverityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeverityLevel::Low => write!(f, "low"),
            SeverityLevel::Medium => write!(f, "medium"),
            SeverityLevel::High => write!(f, "high"),
        }
    }
}

impl From<SeverityLevel> for Severity {
    fn from(level: SeverityLevel) -> Self {
        match level {
            SeverityLevel::Low => Severity::Low,
            SeverityLevel::Medium => Severity::Medium,
            SeverityLevel::High => Severity::High,
        }
    }
}

/// Find the root directory of a Forc project by looking for Forc.toml
fn find_forc_project_root(start_dir: &Path) -> Option<PathBuf> {
    let mut current = start_dir;
    
    loop {
        let forc_toml = current.join("Forc.toml");
        if forc_toml.exists() {
            return Some(current.to_path_buf());
        }
        
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }
    
    None
}