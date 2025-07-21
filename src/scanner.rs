use crate::cli::Args;
use crate::detectors::{DetectorRegistry, Finding};
use crate::error::SwayscanError;
use crate::parser::{SwayParser, SwayFile};
use crate::analyzer::SwayAstAnalyzer;
use crate::reporter::Reporter;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct Scanner {
    args: Args,
    detector_registry: DetectorRegistry,
    reporter: Reporter,
    ast_analyzer: SwayAstAnalyzer,
}

impl Scanner {
    pub fn new(args: Args) -> Result<Self, SwayscanError> {
        if !args.has_input() {
            return Err(SwayscanError::config_error(
                "No input files or directory specified. Use --files or --directory.",
            ));
        }

        let detector_registry = DetectorRegistry::new();
        let reporter = Reporter::new(args.display_format.clone(), args.sorting.clone());
        let ast_analyzer = SwayAstAnalyzer::new();

        Ok(Self {
            args,
            detector_registry,
            reporter,
            ast_analyzer,
        })
    }

    pub fn scan(&mut self) -> Result<Vec<Finding>, SwayscanError> {
        if self.args.verbose {
            println!("Collecting Sway files...");
        }

        let files = self.collect_sway_files()?;
        
        if files.is_empty() {
            return Err(SwayscanError::NoSwayFiles(
                "No .sw files found in the specified paths".to_string(),
            ));
        }

        if self.args.verbose {
            println!("Found {} Sway files", files.len());
            println!("Parsing files with Sway AST...");
        }

        let parsed_files = self.parse_files(files)?;

        if self.args.verbose {
            println!("Running AST-based detectors...");
        }

        let findings = self.run_detectors(parsed_files)?;

        if self.args.verbose {
            println!("AST-based analysis complete. Found {} issues", findings.len());
        }

        Ok(findings)
    }

    pub fn report_results(&self, findings: Vec<Finding>) -> Result<(), SwayscanError> {
        // Generate and save output if --output flag is specified
        if let Some(output_path) = &self.args.output {
            if self.args.verbose {
                println!("Saving report to: {}", output_path.display());
            }
            
            // Check file extension to determine format
            let extension = output_path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("");
            
            match extension.to_lowercase().as_str() {
                "md" | "markdown" => {
                    // Use the beautiful Markdown template
                    let markdown_generator = crate::markdown_generator::MarkdownGenerator::new();
                    let project_name = self.args.directory.as_ref()
                        .and_then(|p| p.file_name())
                        .and_then(|n| n.to_str())
                        .or_else(|| {
                            self.args.files.get(0)
                                .and_then(|f| f.file_stem())
                                .and_then(|n| n.to_str())
                        });
                    
                    markdown_generator.generate_report(&findings, output_path, project_name)
                        .map_err(|e| SwayscanError::FileNotFound(format!("Failed to generate Markdown report: {}", e)))?;
                }
                "json" => {
                    // Generate JSON format
                    let report_content = serde_json::to_string_pretty(&findings)
                        .map_err(|e| SwayscanError::FileNotFound(format!("JSON serialization error: {}", e)))?;
                    std::fs::write(output_path, report_content)
                        .map_err(|e| SwayscanError::FileNotFound(format!("Failed to write to {}: {}", output_path.display(), e)))?;
                }
                _ => {
                    // Default to text format for other extensions
                    let report_content = self.generate_text_report(&findings);
                    std::fs::write(output_path, report_content)
                        .map_err(|e| SwayscanError::FileNotFound(format!("Failed to write to {}: {}", output_path.display(), e)))?;
                }
            }
            
            if self.args.verbose {
                println!("✅ Report saved to: {}", output_path.display());
            }
        } else {
            // Default behavior - print to stdout with grouped findings
            let grouped_findings = crate::detectors::group_findings(findings.clone());
            self.reporter.report_grouped(grouped_findings)?;
        }
        
        // Generate Markdown report if --markdown-report flag is specified (separate from --output)
        if self.args.should_generate_markdown() {
            if self.args.verbose {
                println!("Generating additional Markdown security audit report...");
            }
            
            let markdown_generator = crate::markdown_generator::MarkdownGenerator::new();
            let project_name = self.args.directory.as_ref()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .or_else(|| {
                    self.args.files.get(0)
                        .and_then(|f| f.file_stem())
                        .and_then(|n| n.to_str())
                });
            
            match markdown_generator.generate_report(
                &findings,
                &self.args.markdown_report.as_ref().unwrap(),
                project_name,
            ) {
                Ok(()) => {
                    if self.args.verbose {
                        println!("✅ Additional Markdown report generated: {:?}", self.args.markdown_report.as_ref().unwrap());
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to generate additional Markdown report: {}", e);
                }
            }
        }
        
        Ok(())
    }

    fn generate_pdf_report(&self, _findings: &[Finding], _output_path: &std::path::Path) -> Result<(), SwayscanError> {
        // PDF generation removed - use --markdown-report for professional reports
        eprintln!("PDF generation has been removed. Use --markdown-report instead for professional audit reports.");
        Ok(())
    }

    fn generate_text_report(&self, findings: &[Finding]) -> String {
        let mut output = String::new();
        
        output.push_str("SwayScanner AST-Based Analysis Report\n");
        output.push_str(&"═".repeat(54));
        output.push('\n');
        output.push_str(&format!("{} findings found:\n\n", findings.len()));

        for finding in findings {
            output.push_str(&format!("[{}] {} ({})\n", 
                finding.severity.as_str(),
                finding.title,
                finding.detector_name
            ));
            output.push_str(&format!("   Location: {}:{}\n", 
                finding.file_path,
                finding.line
            ));
            output.push_str(&format!("   Description: {}\n", finding.description));
            
            if !finding.code_snippet.is_empty() {
                output.push_str(&format!("   Code: {}\n", finding.code_snippet));
            }
            
            output.push_str(&format!("   Recommendation: {}\n\n", finding.recommendation));
        }

        output.push_str(&"═".repeat(54));
        output.push_str("\nAST-based analysis completed by SwayScanner\n");
        
        output
    }

    fn collect_sway_files(&self) -> Result<Vec<PathBuf>, SwayscanError> {
        let mut files = Vec::new();

        // Add files from --files argument
        for file_path in &self.args.files {
            if file_path.is_dir() {
                // If a directory is passed via --files, scan it recursively
                for entry in WalkDir::new(file_path)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    if entry.file_type().is_file() && self.is_sway_file(entry.path()) {
                        files.push(entry.path().to_path_buf());
                    }
                }
            } else if file_path.is_file() && self.is_sway_file(file_path) {
                files.push(file_path.clone());
            }
        }

        // Add files from --directory argument
        if let Some(dir_path) = &self.args.directory {
            for entry in WalkDir::new(dir_path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() && self.is_sway_file(entry.path()) {
                    files.push(entry.path().to_path_buf());
                }
            }
        }

        // Remove duplicates and sort
        files.sort();
        files.dedup();

        Ok(files)
    }

    fn is_sway_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext == "sw")
            .unwrap_or(false)
    }

    fn parse_files(&self, file_paths: Vec<PathBuf>) -> Result<Vec<SwayFile>, SwayscanError> {
        let mut parsed_files = Vec::new();

        for file_path in file_paths {
            match SwayParser::parse_file(&file_path) {
                Ok(parsed_file) => {
                    if self.args.verbose {
                        println!("✅ Parsed: {}", file_path.display());
                    }
                    parsed_files.push(parsed_file);
                }
                Err(e) => {
                    if self.args.verbose {
                        eprintln!("❌ Failed to parse {}: {}", file_path.display(), e);
                    }
                    // Continue with other files even if one fails
                }
            }
        }

        Ok(parsed_files)
    }

    fn run_detectors(&mut self, files: Vec<SwayFile>) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();
        let mut processed_functions = std::collections::HashSet::new();
        let selected_detectors = self.detector_registry.get_selected_detectors(
            &self.args.detectors,
            &self.args.exclude_detectors,
        );

            if self.args.verbose {
            println!("Running {} detectors on {} files", selected_detectors.len(), files.len());
            for detector in &selected_detectors {
                println!("  - {}", detector.name());
            }
        }

        for file in files {
            if self.args.verbose {
                println!("Analyzing: {}", file.path);
            }

            // Use AST-based analysis for each file
            let analysis_context = self.ast_analyzer.analyze_file(&file);

            for detector in &selected_detectors {
                if detector.supports_file_type(&file.path) {
                    match detector.analyze(&file, &analysis_context) {
                        Ok(findings) => {
                            // Filter findings based on confidence threshold and deduplication
                            let filtered_findings: Vec<Finding> = findings
                                .into_iter()
                                .filter(|finding| {
                                    // Check confidence threshold
                                    if finding.confidence < self.args.confidence_threshold {
                                        return false;
                                    }
                                    
                                    // Check for duplicates across files
                                    // Use a more specific key that includes function name, line number, and file path
                                    let unknown = "unknown".to_string();
                                    let function_name = finding.context.function_name.as_ref()
                                        .unwrap_or(&unknown);
                                    
                                    // Create a unique key that considers multiple factors including function name
                                    let key = format!("{}:{}:{}:{}:{}", 
                                        function_name,
                                        detector.name(), 
                                        &finding.title,
                                        finding.line,
                                        finding.file_path
                                    );
                                    
                                    if !processed_functions.contains(&key) {
                                        processed_functions.insert(key);
                                        true
                                } else {
                                        false
                                }
                                })
                                .collect();

                            if self.args.verbose && !filtered_findings.is_empty() {
                                println!("  {}: Found {} issues", detector.name(), filtered_findings.len());
                            }

                            all_findings.extend(filtered_findings);
                        }
                        Err(e) => {
                            if self.args.verbose {
                                eprintln!("  ❌ {}: Error - {}", detector.name(), e);
                            }
                        }
                    }
                }
            }
        }

        // Filter by severity if specified
        if let Some(severity_filter) = &self.args.severity_filter {
            all_findings.retain(|finding| finding.severity >= severity_filter.clone().into());
        }

        // Sort findings
        all_findings.sort_by(|a, b| {
            // Primary sort: severity (descending)
            let severity_cmp = b.severity.cmp(&a.severity);
            if severity_cmp != std::cmp::Ordering::Equal {
                return severity_cmp;
            }
            
            // Secondary sort: confidence (descending)
            b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(all_findings)
    }

    fn extract_function_name_from_finding(&self, finding: &Finding, file: &SwayFile) -> Option<String> {
        // Extract function name from the finding's line number
        let lines: Vec<&str> = file.content.lines().collect();
        let line_num = finding.line.saturating_sub(1);
        
        if line_num < lines.len() {
            let line = lines[line_num];
            
            // Look for function definition patterns
            if line.contains("fn ") {
                // Extract function name from "fn function_name("
                if let Some(fn_start) = line.find("fn ") {
                    let after_fn = &line[fn_start + 3..];
                    if let Some(paren_start) = after_fn.find('(') {
                        return Some(after_fn[..paren_start].trim().to_string());
                    }
                }
            }
        }
        
        None
    }
}