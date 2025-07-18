use crate::detectors::{Finding, Severity, Category};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct MarkdownGenerator;

impl MarkdownGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_report<P: AsRef<Path>>(
        &self,
        findings: &[Finding],
        output_path: P,
        project_name: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut content = String::new();
        
        // Header
        content.push_str(&self.generate_header(project_name, findings));
        
        // Executive Summary
        content.push_str(&self.generate_executive_summary(findings));
        
        // Statistics
        content.push_str(&self.generate_statistics(findings));
        
        // Findings by Severity
        content.push_str(&self.generate_findings_by_severity(findings));
        
        // Detailed Findings
        content.push_str(&self.generate_detailed_findings(findings));
        
        // Recommendations
        content.push_str(&self.generate_recommendations(findings));
        
        // Footer
        content.push_str(&self.generate_footer());
        
        fs::write(output_path, content)?;
        Ok(())
    }

    fn generate_header(&self, project_name: Option<&str>, findings: &[Finding]) -> String {
        let project = project_name.unwrap_or("Sway Smart Contract");
        let total_issues = findings.len();
        let date = chrono::Utc::now().format("%B %d, %Y").to_string();
        
        format!(r#"# 🛡️ Security Audit Report

## 📋 Project Information

| Field | Value |
|-------|-------|
| **Project Name** | {} |
| **Audit Date** | {} |
| **Total Issues Found** | {} |
| **Auditor** | Safe Edges Security |
| **Report Version** | 1.0 |

---

"#, project, date, total_issues)
    }

    fn generate_executive_summary(&self, findings: &[Finding]) -> String {
        let mut summary = String::from("## 📊 Executive Summary\n\n");
        
        let critical_count = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
        let high_count = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
        let medium_count = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count();
        let low_count = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count();
        
        if critical_count > 0 || high_count > 0 {
            summary.push_str("⚠️ **CRITICAL ATTENTION REQUIRED** - High or Critical severity vulnerabilities detected.\n\n");
        } else if medium_count > 0 {
            summary.push_str("⚡ **MODERATE RISK** - Medium severity issues require attention.\n\n");
        } else {
            summary.push_str("✅ **LOW RISK** - Only low-severity issues detected.\n\n");
        }
        
        summary.push_str("### Risk Level Distribution\n\n");
        summary.push_str("| Severity | Count | Risk Level |\n");
        summary.push_str("|----------|-------|------------|\n");
        
        if critical_count > 0 {
            summary.push_str(&format!("| 🔴 **Critical** | {} | Immediate action required |\n", critical_count));
        }
        if high_count > 0 {
            summary.push_str(&format!("| 🟠 **High** | {} | Priority fix needed |\n", high_count));
        }
        if medium_count > 0 {
            summary.push_str(&format!("| 🟡 **Medium** | {} | Should be addressed |\n", medium_count));
        }
        if low_count > 0 {
            summary.push_str(&format!("| 🟢 **Low** | {} | Minor improvements |\n", low_count));
        }
        
        summary.push_str("\n---\n\n");
        summary
    }

    fn generate_statistics(&self, findings: &[Finding]) -> String {
        let mut stats = String::from("## 📈 Analysis Statistics\n\n");
        
        // Group by detector
        let mut detector_count: HashMap<String, usize> = HashMap::new();
        for finding in findings {
            *detector_count.entry(finding.detector_name.clone()).or_insert(0) += 1;
        }
        
        // Group by category
        let mut category_count: HashMap<Category, usize> = HashMap::new();
        for finding in findings {
            *category_count.entry(finding.category.clone()).or_insert(0) += 1;
        }
        
        stats.push_str("### Issues by Category\n\n");
        stats.push_str("| Category | Count | Percentage |\n");
        stats.push_str("|----------|-------|------------|\n");
        
        let total = findings.len() as f64;
        for (category, count) in category_count.iter() {
            let percentage = ((*count as f64) / total * 100.0).round() as u32;
            let icon = match category {
                Category::Security => "🔒",
                Category::Performance => "⚡",
                Category::Maintainability => "🔧",
                Category::Reliability => "🛡️",
                Category::Compliance => "📋",
            };
            stats.push_str(&format!("| {} {} | {} | {}% |\n", 
                icon, format!("{:?}", category), count, percentage));
        }
        
        stats.push_str("\n### Top Detectors\n\n");
        let mut detector_vec: Vec<_> = detector_count.iter().collect();
        detector_vec.sort_by(|a, b| b.1.cmp(a.1));
        
        stats.push_str("| Detector | Issues Found |\n");
        stats.push_str("|----------|-------------|\n");
        
        for (detector, count) in detector_vec.iter().take(5) {
            stats.push_str(&format!("| `{}` | {} |\n", detector, count));
        }
        
        stats.push_str("\n---\n\n");
        stats
    }

    fn generate_findings_by_severity(&self, findings: &[Finding]) -> String {
        let mut content = String::from("## 🔍 Findings by Severity\n\n");
        
        let severities = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low];
        
        for severity in severities {
            let severity_findings: Vec<_> = findings.iter()
                .filter(|f| f.severity == severity)
                .collect();
                
            if severity_findings.is_empty() {
                continue;
            }
            
            let (icon, color) = match severity {
                Severity::Critical => ("🔴", "Critical"),
                Severity::High => ("🟠", "High"),
                Severity::Medium => ("🟡", "Medium"),
                Severity::Low => ("🟢", "Low"),
            };
            
            content.push_str(&format!("### {} {} Severity ({} issues)\n\n", 
                icon, color, severity_findings.len()));
            
            for finding in severity_findings.iter().take(10) { // Limit to first 10
                let file_name = finding.file_path.split(['/', '\\']).last().unwrap_or(&finding.file_path);
                content.push_str(&format!("- **{}** in `{}:{}` - {}\n", 
                    finding.title, file_name, finding.line, 
                    finding.description.lines().next().unwrap_or("").trim()));
            }
            
            if severity_findings.len() > 10 {
                content.push_str(&format!("- *... and {} more {} severity issues*\n", 
                    severity_findings.len() - 10, color.to_lowercase()));
            }
            
            content.push_str("\n");
        }
        
        content.push_str("---\n\n");
        content
    }

    fn generate_detailed_findings(&self, findings: &[Finding]) -> String {
        let mut content = String::from("## 📝 Detailed Findings\n\n");
        
        for (index, finding) in findings.iter().enumerate() {
            let (icon, _) = match finding.severity {
                Severity::Critical => ("🔴", "Critical"),
                Severity::High => ("🟠", "High"),
                Severity::Medium => ("🟡", "Medium"),
                Severity::Low => ("🟢", "Low"),
            };
            
            let file_name = finding.file_path.split(['/', '\\']).last().unwrap_or(&finding.file_path);
            
            content.push_str(&format!("### {} {}\n\n", icon, finding.title));
            content.push_str(&format!("**Severity:** {:?} | **Category:** {:?} | **Confidence:** {:.1}%\n\n", 
                finding.severity, finding.category, finding.confidence * 100.0));
            content.push_str(&format!("**Location:** `{}:{}:{}`\n\n", file_name, finding.line, finding.column));
            
            // Description
            content.push_str("**Description:**\n");
            content.push_str(&format!("{}\n\n", finding.description));
            
            // Code snippet
            if !finding.code_snippet.trim().is_empty() {
                content.push_str("**Code:**\n");
                content.push_str("```rust\n");
                content.push_str(&finding.code_snippet);
                content.push_str("\n```\n\n");
            }
            
            // Recommendation
            content.push_str("**Recommendation:**\n");
            content.push_str(&format!("{}\n\n", finding.recommendation));
            
            // Add separator except for last finding
            if index < findings.len() - 1 {
                content.push_str("---\n\n");
            }
        }
        
        content
    }

    fn generate_recommendations(&self, findings: &[Finding]) -> String {
        let mut content = String::from("## 💡 General Recommendations\n\n");
        
        let critical_count = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
        let high_count = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
        
        content.push_str("### Immediate Actions\n\n");
        
        if critical_count > 0 {
            content.push_str("🚨 **URGENT:** Address all Critical severity issues immediately before deployment.\n\n");
        }
        
        if high_count > 0 {
            content.push_str("🔥 **HIGH PRIORITY:** Resolve High severity vulnerabilities as soon as possible.\n\n");
        }
        
        content.push_str("### Security Best Practices\n\n");
        content.push_str("1. **Access Control:** Implement proper access control checks for all privileged functions\n");
        content.push_str("2. **Input Validation:** Validate all user inputs with appropriate bounds checking\n");
        content.push_str("3. **Reentrancy Protection:** Follow checks-effects-interactions pattern\n");
        content.push_str("4. **UTXO Validation:** Implement proper UTXO double-spend protection\n");
        content.push_str("5. **Oracle Security:** Use multiple price feeds with deviation checks\n");
        content.push_str("6. **Error Handling:** Properly handle all external call failures\n\n");
        
        content.push_str("### Code Quality\n\n");
        content.push_str("- Add comprehensive unit tests for all functions\n");
        content.push_str("- Implement integration tests for complex workflows\n");
        content.push_str("- Add proper documentation and comments\n");
        content.push_str("- Consider formal verification for critical components\n\n");
        
        content.push_str("---\n\n");
        content
    }

    fn generate_footer(&self) -> String {
        let date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
        
        format!(r#"## 📞 Contact Information

**Safe Edges Security**
- Website: [safeedges.in](https://safeedges.in)
- Email: security@safeedges.in
- Specialized in Sway and Fuel ecosystem security

---

*This report was generated by SwayScanner v{} on {}*

**Disclaimer:** This audit report is provided for informational purposes only and does not guarantee the security of the audited smart contract. The auditors have made every effort to identify potential vulnerabilities, but cannot guarantee that all issues have been found. The final responsibility for security lies with the development team.
"#, env!("CARGO_PKG_VERSION"), date)
    }
} 