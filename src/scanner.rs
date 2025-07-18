use crate::cli::Args;
use crate::detectors::{DetectorRegistry, Finding};
use crate::error::SwayscanError;
use crate::parser::{SwayParser, SwayFile};
use crate::reporter::Reporter;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct Scanner {
    args: Args,
    detector_registry: DetectorRegistry,
    reporter: Reporter,
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

        Ok(Self {
            args,
            detector_registry,
            reporter,
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
            println!("Parsing files...");
        }

        let parsed_files = self.parse_files(files)?;

        if self.args.verbose {
            println!("Running detectors...");
        }

        let findings = self.run_detectors(parsed_files)?;

        if self.args.verbose {
            println!("Analysis complete. Found {} issues", findings.len());
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
        
        output.push_str("SwayScanner Analysis Report\n");
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
        output.push_str("\nAnalysis completed by SwayScanner\n");
        
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
                    let path = entry.path();
                    if self.is_sway_file(path) {
                        files.push(path.to_path_buf());
                    }
                }
            } else {
                if !file_path.exists() {
                    return Err(SwayscanError::FileNotFound(
                        file_path.to_string_lossy().to_string(),
                    ));
                }

                if !self.is_sway_file(file_path) {
                    return Err(SwayscanError::InvalidFileExtension(
                        file_path.to_string_lossy().to_string(),
                    ));
                }

                files.push(file_path.clone());
            }
        }

        // Add files from --directory argument
        if let Some(ref directory) = self.args.directory {
            if !directory.exists() {
                return Err(SwayscanError::FileNotFound(
                    directory.to_string_lossy().to_string(),
                ));
            }

            for entry in WalkDir::new(directory)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if self.is_sway_file(path) {
                    files.push(path.to_path_buf());
                }
            }
        }

        // Handle --scan-all flag
        if self.args.scan_all {
            let current_dir = std::env::current_dir()
                .map_err(|e| SwayscanError::config_error(format!("Failed to get current directory: {}", e)))?;
            
            if self.args.verbose {
                println!("Scanning all .sw files recursively from: {}", current_dir.display());
            }

            for entry in WalkDir::new(&current_dir)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if self.is_sway_file(path) {
                    files.push(path.to_path_buf());
                }
            }
        }

        // Remove duplicates
        files.sort();
        files.dedup();

        Ok(files)
    }

    fn is_sway_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("sw"))
            .unwrap_or(false)
    }

    fn parse_files(&self, file_paths: Vec<PathBuf>) -> Result<Vec<SwayFile>, SwayscanError> {
        let mut parsed_files = Vec::new();

        for file_path in file_paths {
            if self.args.verbose {
                println!("Parsing: {}", file_path.display());
            }

            match SwayParser::parse_file(&file_path) {
                Ok(parsed_file) => {
                    parsed_files.push(parsed_file);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to parse {}: {}", file_path.display(), e);
                }
            }
        }

        Ok(parsed_files)
    }

    fn run_detectors(&mut self, files: Vec<SwayFile>) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();

        let detectors = if self.args.should_run_all_detectors() {
            if self.args.verbose {
                println!("Running all {} detectors", self.detector_registry.detector_count());
            }
            self.detector_registry.get_all_detectors()
        } else {
            if self.args.verbose {
                println!("Running {} selected detectors", self.args.detectors.len());
            }
            self.detector_registry.get_selected_detectors(&self.args.detectors, &self.args.exclude_detectors)
        };

        if self.args.verbose {
            println!("Running detectors...");
        }

        for detector in detectors {
            // Remove the individual detector running messages for cleaner output
            for file in &files {
                // Use advanced analyzer with comprehensive analysis
                let mut advanced_analyzer = crate::analyzer::AdvancedAnalyzer::new();
                let context = advanced_analyzer.build_comprehensive_analysis(file);
                
                match detector.analyze(file, &context) {
                    Ok(mut findings) => {
                        // Apply advanced false positive reduction for access control findings
                        if detector.name() == "access_control" {
                            findings.retain(|finding| {
                                // Extract function name from finding description or line
                                if let Some(func_name) = self.extract_function_name_from_finding(finding, file) {
                                    advanced_analyzer.should_flag_access_control(&func_name)
                                } else {
                                    true // Keep finding if we can't determine function
                                }
                            });
                        }
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: Detector '{}' failed on file {}: {}",
                            detector.name(),
                            file.path,
                            e
                        );
                    }
                }
            }
        }

        // Group findings to eliminate duplicates and show all occurrences
        let grouped_findings = crate::detectors::group_findings(all_findings);
        
        // Convert back to individual findings for compatibility
        let mut final_findings = Vec::new();
        for group in grouped_findings {
            if group.locations.len() == 1 {
                // Single occurrence - convert back to regular finding
                final_findings.push(Finding {
                    id: group.id,
                    detector_name: group.detector_name,
                    severity: group.severity,
                    category: group.category,
                    confidence: group.confidence,
                    title: group.title,
                    description: group.description,
                    file_path: group.locations[0].file_path.clone(),
                    line: group.locations[0].line,
                    column: group.locations[0].column,
                    end_line: group.locations[0].end_line,
                    end_column: group.locations[0].end_column,
                    code_snippet: group.locations[0].code_snippet.clone(),
                    recommendation: group.recommendation,
                    impact: group.impact,
                    effort: group.effort,
                    references: group.references,
                    cwe_ids: group.cwe_ids,
                    owasp_category: group.owasp_category,
                    tags: group.tags,
                    created_at: group.created_at,
                    fingerprint: group.fingerprint,
                    context: group.context,
                });
            } else {
                // Multiple occurrences - create one finding with all locations in description
                let locations_desc = group.locations.iter()
                    .map(|loc| format!("  • {}:{} - {}", 
                        loc.file_path.split(['/', '\\']).last().unwrap_or(&loc.file_path),
                        loc.line,
                        loc.code_snippet.lines().next().unwrap_or("").trim()
                    ))
                    .collect::<Vec<_>>()
                    .join("\n");
                
                let enhanced_description = format!(
                    "{}\n\nFound in {} locations:\n{}",
                    group.description,
                    group.locations.len(),
                    locations_desc
                );
                
                final_findings.push(Finding {
                    id: group.id,
                    detector_name: group.detector_name,
                    severity: group.severity,
                    category: group.category,
                    confidence: group.confidence,
                    title: format!("{} ({} occurrences)", group.title, group.locations.len()),
                    description: enhanced_description,
                    file_path: group.locations[0].file_path.clone(),
                    line: group.locations[0].line,
                    column: group.locations[0].column,
                    end_line: group.locations[0].end_line,
                    end_column: group.locations[0].end_column,
                    code_snippet: group.locations[0].code_snippet.clone(),
                    recommendation: group.recommendation,
                    impact: group.impact,
                    effort: group.effort,
                    references: group.references,
                    cwe_ids: group.cwe_ids,
                    owasp_category: group.owasp_category,
                    tags: group.tags,
                    created_at: group.created_at,
                    fingerprint: group.fingerprint,
                    context: group.context,
                });
            }
        }
        
        Ok(final_findings)
    }

    fn extract_function_name_from_finding(&self, finding: &Finding, file: &SwayFile) -> Option<String> {
        // Extract function name from the finding's line number
        let lines: Vec<&str> = file.content.lines().collect();
        let start_line = finding.line.saturating_sub(1);
        
        // Look backwards from the finding line to find the function declaration
        for i in (0..=start_line.min(lines.len().saturating_sub(1))).rev() {
            if let Some(line) = lines.get(i) {
                if let Some(start) = line.find("fn ") {
                    let after_fn = &line[start + 3..];
                    if let Some(end) = after_fn.find('(') {
                        return Some(after_fn[..end].trim().to_string());
                    }
                }
            }
        }
        
        // Fallback: try to extract from finding description
        if finding.description.contains("function") {
            // Look for quoted function names in description
            if let Some(start) = finding.description.find('`') {
                if let Some(end) = finding.description[start + 1..].find('`') {
                    return Some(finding.description[start + 1..start + 1 + end].to_string());
                }
            }
        }
        
        None
    }
}