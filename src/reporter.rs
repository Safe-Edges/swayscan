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
            self.print_no_issues_found();
            return Ok(());
        }

        let total_findings: usize = grouped_findings.iter().map(|g| g.occurrence_count).sum();
        
        self.print_header(&grouped_findings, total_findings);
        self.print_executive_summary(&grouped_findings);
        self.print_detailed_findings(&grouped_findings);
        self.print_summary(&grouped_findings);
        self.print_footer();

        Ok(())
    }

    fn print_no_issues_found(&self) {
        println!();
        println!("{}", "╭─────────────────────────────────────────────────────────╮".bright_green());
        println!("{}", "│                    🛡️  SCAN COMPLETE                     │".bright_green().bold());
        println!("{}", "│                                                         │".bright_green());
        println!("{}", "│              ✅ No security issues found!               │".bright_green().bold());
        println!("{}", "│                                                         │".bright_green());
        println!("{}", "│    Your Sway smart contract appears to be secure       │".bright_green());
        println!("{}", "│    based on our comprehensive security analysis.       │".bright_green());
        println!("{}", "╰─────────────────────────────────────────────────────────╯".bright_green());
        println!();
    }

    fn print_header(&self, grouped_findings: &[GroupedFinding], total_findings: usize) {
        println!();
        println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_cyan().bold());
        println!("{}", "                      🔍 SWAYSCAN SECURITY AUDIT REPORT".bright_cyan().bold());
        println!("{}", "                           Built by Safe Edges Team".bright_blue());
        println!("{}", "                             https://safeedges.in".bright_blue().underline());
        println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_cyan().bold());
        println!();
        
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        println!("{} {}", "📅 Scan Date:".bright_white().bold(), timestamp.to_string().white());
        println!("{} SwayScanner v{}", "🔧 Tool Version:".bright_white().bold(), env!("CARGO_PKG_VERSION").white());
        println!("{} {} unique vulnerabilities ({} total occurrences)", 
            "📊 Issues Found:".bright_white().bold(), 
            grouped_findings.len().to_string().red().bold(),
            total_findings.to_string().yellow().bold()
        );
        println!();
    }

    fn print_executive_summary(&self, grouped_findings: &[GroupedFinding]) {
        println!("{}", "╭─────────────────────────────────────────────────────────╮".bright_white());
        println!("{}", "│                  📋 EXECUTIVE SUMMARY                   │".bright_white().bold());
        println!("{}", "╰─────────────────────────────────────────────────────────╯".bright_white());
        println!();

        // Count by severity
        let critical_count = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::Critical)).count();
        let high_count = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::High)).count();
        let medium_count = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::Medium)).count();
        let low_count = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::Low)).count();

        // Risk assessment
        let risk_level = if critical_count > 0 {
            "🔴 CRITICAL RISK".red().bold()
        } else if high_count > 3 {
            "🟠 HIGH RISK".red().bold()
        } else if high_count > 0 || medium_count > 5 {
            "🟡 MEDIUM RISK".yellow().bold()
        } else {
            "🟢 LOW RISK".green().bold()
        };

        println!("{} {}", "🎯 Overall Risk Level:".bright_white().bold(), risk_level);
        println!();

        println!("{}", "Severity Breakdown:".bright_white().bold());
        if critical_count > 0 {
            println!("  {} {} issues - {}", 
                "💀".red(), 
                critical_count.to_string().red().bold(),
                "Immediate action required".red().bold()
            );
        }
        if high_count > 0 {
            println!("  {} {} issues - {}", 
                "🔴".red(), 
                high_count.to_string().red().bold(),
                "Fix before deployment".red()
            );
        }
        if medium_count > 0 {
            println!("  {} {} issues - {}", 
                "🟡".yellow(), 
                medium_count.to_string().yellow().bold(),
                "Address when possible".yellow()
            );
        }
        if low_count > 0 {
            println!("  {} {} issues - {}", 
                "🟢".green(), 
                low_count.to_string().green().bold(),
                "Consider fixing".green()
            );
        }

        // Top vulnerability categories
        let mut category_counts = std::collections::HashMap::new();
        for finding in grouped_findings {
            *category_counts.entry(&finding.detector_name).or_insert(0) += 1;
        }
        
        if !category_counts.is_empty() {
            println!();
            println!("{}", "Top Vulnerability Categories:".bright_white().bold());
            let mut categories: Vec<_> = category_counts.iter().collect();
            categories.sort_by(|a, b| b.1.cmp(a.1));
            
            for (category, count) in categories.iter().take(3) {
                let category_display = self.format_detector_name(category);
                println!("  • {} ({} occurrences)", category_display.bright_cyan(), count.to_string().cyan().bold());
            }
        }

        println!();
        println!("{}", "─".repeat(75).bright_black());
        println!();
    }

    fn print_detailed_findings(&self, grouped_findings: &[GroupedFinding]) {
        println!("{}", "╭─────────────────────────────────────────────────────────╮".bright_white());
        println!("{}", "│                   🔍 DETAILED FINDINGS                  │".bright_white().bold());
        println!("{}", "╰─────────────────────────────────────────────────────────╯".bright_white());
        println!();

        for (index, group) in grouped_findings.iter().enumerate() {
            self.print_finding_detail(index + 1, group);
            
            if index < grouped_findings.len() - 1 {
                println!("{}", "─".repeat(75).bright_black());
                println!();
            }
        }
    }

    fn print_finding_detail(&self, index: usize, group: &GroupedFinding) {
        let severity_indicator = self.get_severity_indicator(&group.severity);
        let severity_color = self.get_severity_color(&group.severity);
        
        println!("{} {} {}", 
            format!("#{:02}", index).bright_black(),
            severity_indicator,
            group.title.color(severity_color).bold()
        );
        
        // Metadata line
        println!("    {} {} | {} {} | {} {:.1}%", 
            "Detector:".bright_black(),
            self.format_detector_name(&group.detector_name).cyan(),
            "Occurrences:".bright_black(),
            group.occurrence_count.to_string().white().bold(),
            "Confidence:".bright_black(),
            (group.confidence * 100.0).to_string().white().bold()
        );
        
        if !group.cwe_ids.is_empty() {
            println!("    {} {}", 
                "CWE IDs:".bright_black(),
                group.cwe_ids.iter().map(|id| format!("CWE-{}", id)).collect::<Vec<_>>().join(", ").bright_blue()
            );
        }
        
        println!();
        
        // Description with proper wrapping
        println!("    {}", "📝 Description:".bright_white().bold());
        self.print_wrapped_text(&group.description, "       ");
        println!();
        
        // Locations
        if group.locations.len() == 1 {
            println!("    {}", "📍 Location:".bright_white().bold());
        } else {
            println!("    {} ({} occurrences)", "📍 Locations:".bright_white().bold(), group.locations.len());
        }
        
        for (i, location) in group.locations.iter().enumerate() {
            let prefix = if group.locations.len() == 1 {
                "       "
            } else if i == group.locations.len() - 1 {
                "       └─ "
            } else {
                "       ├─ "
            };
            
            println!("{}{}", prefix, format!("{}:{}", location.file_path, location.line).bright_yellow());
            
            if let Some(function_name) = &location.function_name {
                println!("{}   {} {}", prefix, "Function:".bright_black(), function_name.white());
            }
            
            if !location.code_snippet.is_empty() {
                println!("{}   {} {}", prefix, "Code:".bright_black(), location.code_snippet.bright_black());
            }
            
            if i < group.locations.len() - 1 {
                println!();
            }
        }
        
        println!();
        
        // Impact
        if !group.impact.is_empty() {
            println!("    {}", "💥 Impact:".bright_red().bold());
            self.print_wrapped_text(&group.impact, "       ");
            println!();
        }
        
        // Recommendation
        if !group.recommendation.is_empty() {
            println!("    {}", "🔧 Recommendation:".bright_green().bold());
            self.print_wrapped_text(&group.recommendation, "       ");
            println!();
        }
        
        // References
        if !group.references.is_empty() {
            println!("    {}", "📚 References:".bright_blue().bold());
            for reference in &group.references {
                println!("       • {} ({})", reference.title.bright_blue().underline(), reference.url.bright_black());
            }
            println!();
        }
    }

    fn print_summary(&self, grouped_findings: &[GroupedFinding]) {
        println!("{}", "╭─────────────────────────────────────────────────────────╮".bright_white());
        println!("{}", "│                     📊 SCAN SUMMARY                     │".bright_white().bold());
        println!("{}", "╰─────────────────────────────────────────────────────────╯".bright_white());
        println!();

        let critical_count = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::Critical)).count();
        let high_count = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::High)).count();
        let medium_count = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::Medium)).count();
        let low_count = grouped_findings.iter().filter(|g| matches!(g.severity, Severity::Low)).count();

        println!("{}", "Severity Distribution:".bright_white().bold());
        println!("  {} Critical: {}", "💀".red(), critical_count.to_string().red().bold());
        println!("  {} High: {}", "🔴".red(), high_count.to_string().red().bold());
        println!("  {} Medium: {}", "🟡".yellow(), medium_count.to_string().yellow().bold());
        println!("  {} Low: {}", "🟢".green(), low_count.to_string().green().bold());
        println!();

        // Recommendations
        println!("{}", "🎯 Next Steps:".bright_white().bold());
        if critical_count > 0 || high_count > 0 {
            println!("  1. {} Address all critical and high-severity vulnerabilities immediately", "🚨".red());
            println!("  2. {} Conduct thorough testing after fixes", "🧪".yellow());
            println!("  3. {} Consider professional security audit", "🔍".blue());
        } else if medium_count > 0 {
            println!("  1. {} Review and address medium-severity issues", "📋".yellow());
            println!("  2. {} Test fixes thoroughly", "🧪".green());
        } else {
            println!("  1. {} Address remaining low-severity issues when possible", "📝".green());
            println!("  2. {} Maintain good security practices", "🛡️".green());
        }
        
        if grouped_findings.len() > 0 {
            println!("  4. {} Re-run SwayScanner to verify fixes", "🔄".cyan());
        }
    }

    fn print_footer(&self) {
        println!();
        println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_cyan());
        println!("{}", "                        Analysis completed by SwayScanner".bright_cyan());
        println!("{}", "                    🛡️  Built by Safe Edges Team - Securing Web3".bright_blue());
        println!("{}", "                      📧 Contact: info@safeedges.in".bright_blue());
        println!("{}", "                         🌐 https://safeedges.in".bright_blue().underline());
        println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_cyan());
        println!();
    }

    fn get_severity_indicator(&self, severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "💀 CRITICAL",
            Severity::High => "🔴 HIGH",
            Severity::Medium => "🟡 MEDIUM",
            Severity::Low => "🟢 LOW",
        }
    }

    fn get_severity_color(&self, severity: &Severity) -> Color {
        match severity {
            Severity::Critical => Color::Magenta,
            Severity::High => Color::Red,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Green,
        }
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

    fn print_wrapped_text(&self, text: &str, prefix: &str) {
        let max_width = 75 - prefix.len();
        let words: Vec<&str> = text.split_whitespace().collect();
        let mut current_line = String::new();
        
        for word in words {
            if current_line.len() + word.len() + 1 > max_width && !current_line.is_empty() {
                println!("{}{}", prefix, current_line.white());
                current_line.clear();
            }
            
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
        
        if !current_line.is_empty() {
            println!("{}{}", prefix, current_line.white());
        }
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
            self.print_no_issues_found();
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