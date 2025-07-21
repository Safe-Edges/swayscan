use crate::detectors::{Finding, GroupedFinding, Severity};
use crate::cli::{OutputFormat, SortOrder};
use crate::error::SwayscanError;
use colored::*;

pub struct Reporter {
    output_format: OutputFormat,
    sort_order: SortOrder,
}

impl Reporter {
    pub fn new(format: OutputFormat, sort_order: SortOrder) -> Self {
        Self {
            output_format: format,
            sort_order,
        }
    }

    pub fn report_grouped(&self, grouped_findings: Vec<GroupedFinding>) -> Result<(), SwayscanError> {
        match self.output_format {
            OutputFormat::Text => self.report_text_grouped(grouped_findings),
            OutputFormat::Json => self.report_json_grouped(grouped_findings),
            OutputFormat::Sarif => self.report_sarif_grouped(grouped_findings),
            OutputFormat::Csv => self.report_csv_grouped(grouped_findings),
        }
    }

    fn report_text_grouped(&self, grouped_findings: Vec<GroupedFinding>) -> Result<(), SwayscanError> {
        if grouped_findings.is_empty() {
            self.print_no_issues();
            return Ok(());
        }

        self.print_simple_header(&grouped_findings);
        self.print_simple_findings(&grouped_findings);
        self.print_simple_footer();

        Ok(())
    }

    fn print_no_issues(&self) {
        println!();
        println!("{}", "✅ SCAN COMPLETE - NO ISSUES FOUND".bright_green().bold());
        println!("{}", "Your Sway contract appears secure.".green());
        println!();
    }

    fn print_simple_header(&self, grouped_findings: &[GroupedFinding]) {
        println!();
        println!("{}", "🔍 SWAYSCAN SECURITY REPORT".bright_cyan().bold());
        println!("{}", "═".repeat(50).cyan());
        
        let total_findings: usize = grouped_findings.iter().map(|g| g.occurrence_count).sum();
        let critical = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::Critical)).count();
        let high = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::High)).count();
        let medium = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::Medium)).count();
        let low = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::Low)).count();

        println!("Found {} issues ({} total occurrences)", grouped_findings.len(), total_findings);
        println!();
        
        if critical > 0 { println!("💀 {} Critical", critical.to_string().red().bold()); }
        if high > 0 { println!("🔴 {} High", high.to_string().red().bold()); }
        if medium > 0 { println!("🟡 {} Medium", medium.to_string().yellow().bold()); }
        if low > 0 { println!("🟢 {} Low", low.to_string().green().bold()); }
        println!();
    }

    fn print_simple_findings(&self, grouped_findings: &[GroupedFinding]) {
        // Sort by severity (Critical first)
        let mut sorted_findings = grouped_findings.to_vec();
        sorted_findings.sort_by(|a, b| {
            use Severity::*;
            let order_a = match a.severity { Critical => 0, High => 1, Medium => 2, Low => 3 };
            let order_b = match b.severity { Critical => 0, High => 1, Medium => 2, Low => 3 };
            order_a.cmp(&order_b)
        });

        for (index, finding) in sorted_findings.iter().enumerate() {
            self.print_simple_finding(index + 1, finding);
            if index < sorted_findings.len() - 1 {
                println!("{}", "─".repeat(50).bright_black());
            }
        }
    }

    fn print_simple_finding(&self, index: usize, finding: &GroupedFinding) {
        let severity_badge = match finding.severity {
            Severity::Critical => "💀 CRITICAL".red().bold(),
            Severity::High => "🔴 HIGH".red().bold(),
            Severity::Medium => "🟡 MEDIUM".yellow().bold(),
            Severity::Low => "🟢 LOW".green().bold(),
        };

        println!();
        println!("{} {} {}", 
            format!("{}.", index).bright_black(),
            severity_badge,
            finding.title.white().bold()
        );
        
        println!(); // Space after title
        
        println!("   {}", finding.description.white());
        
        println!(); // Space after description
        
        // Show each location as a separate finding with individual titles
        if finding.locations.len() == 1 {
            let loc = &finding.locations[0];
            println!("   📍 {}:{}", loc.file_path.bright_yellow(), loc.line.to_string().bright_yellow());
            if !loc.code_snippet.is_empty() {
                println!("      {}", loc.code_snippet.bright_white());
            }
        } else {
            println!("   📍 {} locations:", finding.locations.len());
            println!(); // Extra space before locations
            
            for (i, loc) in finding.locations.iter().enumerate() {
                // Show each function as a separate sub-finding with exact line number
                println!("   {}. {} at line {}", 
                    (i + 1).to_string().bright_cyan(), 
                    finding.title.white().bold(),
                    loc.line.to_string().bright_yellow()
                );
                println!("      📍 {}:{}", loc.file_path.bright_yellow(), loc.line.to_string().bright_yellow());
                if !loc.code_snippet.is_empty() {
                    println!("      Code: {}", loc.code_snippet.bright_white());
                }
                println!(); // Space between each location
            }
        }

        if !finding.recommendation.is_empty() {
            println!(); // Space before recommendation
            println!("   💡 {}", finding.recommendation.bright_green());
        }
        println!(); // Space after finding
    }

    fn print_simple_footer(&self) {
        println!("{}", "═".repeat(50).cyan());
        println!("{}", "🛡️  SwayScanner by Safe Edges • https://safeedges.in".bright_blue());
        println!();
    }

    fn format_detector_name(&self, name: &str) -> String {
        match name {
            "access_control" => "Access Control",
            "reentrancy_vulnerability" => "Reentrancy Attack",
            "input_validation" => "Input Validation",
            "data_validation" => "Data Validation",
            "unchecked_external_calls" => "Unchecked External Calls",
            "unprotected_storage_variable" => "Unprotected Storage",
            "business_logic" => "Business Logic",
            "cryptographic_issues" => "Cryptographic Issues",
            "price_oracle_manipulation" => "Price Oracle Manipulation",
            "flash_loan_attacks" => "Flash Loan Attacks",
            "utxo_vulnerabilities" => "UTXO Vulnerabilities",
            "logic_errors" => "Logic Errors",
            _ => name
        }.to_string()
    }

    // Simplified versions for other formats
    fn report_json_grouped(&self, grouped_findings: Vec<GroupedFinding>) -> Result<(), SwayscanError> {
        let output = serde_json::to_string_pretty(&grouped_findings)
            .map_err(|e| SwayscanError::config_error(format!("JSON serialization failed: {}", e)))?;
        println!("{}", output);
        Ok(())
    }

    fn report_sarif_grouped(&self, _grouped_findings: Vec<GroupedFinding>) -> Result<(), SwayscanError> {
        println!("SARIF format not yet implemented for grouped findings");
        Ok(())
    }

    fn report_csv_grouped(&self, _grouped_findings: Vec<GroupedFinding>) -> Result<(), SwayscanError> {
        println!("CSV format not yet implemented for grouped findings");
        Ok(())
    }

    // Legacy methods for ungrouped findings
    pub fn report_ungrouped(&self, findings: Vec<Finding>) -> Result<(), SwayscanError> {
        match self.output_format {
            OutputFormat::Text => self.report_text(findings),
            OutputFormat::Json => self.report_json(findings),
            OutputFormat::Sarif => self.report_sarif(findings),
            OutputFormat::Csv => self.report_csv(findings),
        }
    }

    fn report_text(&self, findings: Vec<Finding>) -> Result<(), SwayscanError> {
        if findings.is_empty() {
            self.print_no_issues();
            return Ok(());
        }

        println!("SwayScanner Analysis Report");
        println!("══════════════════════════════════════════════════════");
        println!("{} findings found:", findings.len());

        for finding in &findings {
            println!("\n[{}] {} ({})", finding.severity.as_str(), finding.title, finding.detector_name);
            println!("   Location: {}:{}", finding.file_path, finding.line);
            println!("   Description: {}", finding.description);
            if !finding.code_snippet.is_empty() {
                println!("   Code: {}", finding.code_snippet);
            }
            if !finding.recommendation.is_empty() {
                println!("   Recommendation: {}", finding.recommendation);
            }
        }

        println!("\n═══════════════════════════════════════════════════════");
        println!("Analysis completed by SwayScanner");

        Ok(())
    }

    fn report_json(&self, findings: Vec<Finding>) -> Result<(), SwayscanError> {
        let output = serde_json::to_string_pretty(&findings)
            .map_err(|e| SwayscanError::config_error(format!("JSON serialization failed: {}", e)))?;
        println!("{}", output);
        Ok(())
    }

    fn report_sarif(&self, _findings: Vec<Finding>) -> Result<(), SwayscanError> {
        println!("SARIF format not yet implemented");
        Ok(())
    }

    fn report_csv(&self, _findings: Vec<Finding>) -> Result<(), SwayscanError> {
        println!("CSV format not yet implemented");
        Ok(())
    }
}