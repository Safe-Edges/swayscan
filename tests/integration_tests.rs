use swayscan::{Scanner, SwayFile};
use std::path::PathBuf;
use tempfile::NamedTempFile;
use std::io::Write;

#[test]
fn test_scanner_basic_functionality() {
    let scanner = Scanner::new();
    
    // Create a temporary Sway file with a simple vulnerability
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(
        temp_file,
        r#"
contract TestContract {{
    storage {{
        owner: Identity = Identity::Address(Address::zero()),
        balances: StorageMap<Identity, u64> = StorageMap {{}},
    }}
}}

impl TestContract for Contract {{
    #[storage(read, write)]
    fn unsafe_mint(to: Identity, amount: u64) {{
        // Missing access control - should be detected
        let balance = storage.balances.get(to).try_read().unwrap_or(0);
        storage.balances.insert(to, balance + amount);
    }}
}}
        "#
    ).unwrap();
    
    let file_path = temp_file.path().to_path_buf();
    let content = std::fs::read_to_string(&file_path).unwrap();
    
    let sway_file = SwayFile {
        path: file_path.clone(),
        content,
    };
    
    // Run analysis
    let findings = scanner.analyze_file(&sway_file).unwrap();
    
    // Should detect at least the access control issue
    assert!(!findings.is_empty(), "Scanner should detect vulnerabilities in test contract");
    
    // Check if access control detector flagged the issue
    let has_access_control_finding = findings.iter().any(|f| f.detector_name == "access_control");
    assert!(has_access_control_finding, "Should detect missing access control");
}

#[test]
fn test_scanner_with_secure_contract() {
    let scanner = Scanner::new();
    
    // Create a temporary Sway file with secure patterns
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(
        temp_file,
        r#"
contract SecureContract {{
    storage {{
        owner: Identity = Identity::Address(Address::zero()),
        balances: StorageMap<Identity, u64> = StorageMap {{}},
    }}
}}

impl SecureContract for Contract {{
    #[storage(read)]
    fn get_balance(user: Identity) -> u64 {{
        // This is a read-only function, should not trigger issues
        storage.balances.get(user).try_read().unwrap_or(0)
    }}
    
    #[storage(read, write)]
    fn secure_mint(to: Identity, amount: u64) {{
        // Proper access control
        require(msg_sender().unwrap() == storage.owner.read(), "Only owner");
        
        // Input validation
        require(amount > 0, "Amount must be positive");
        require(amount <= 1000000, "Amount too large");
        
        let balance = storage.balances.get(to).try_read().unwrap_or(0);
        storage.balances.insert(to, balance + amount);
    }}
}}
        "#
    ).unwrap();
    
    let file_path = temp_file.path().to_path_buf();
    let content = std::fs::read_to_string(&file_path).unwrap();
    
    let sway_file = SwayFile {
        path: file_path,
        content,
    };
    
    // Run analysis
    let findings = scanner.analyze_file(&sway_file).unwrap();
    
    // Secure contract should have minimal or no high-severity findings
    let high_severity_findings: Vec<_> = findings.iter()
        .filter(|f| matches!(f.severity, swayscan::Severity::High | swayscan::Severity::Critical))
        .collect();
    
    assert!(
        high_severity_findings.is_empty(), 
        "Secure contract should not have high-severity findings, found: {:?}", 
        high_severity_findings
    );
}

#[test]
fn test_detector_list() {
    let scanner = Scanner::new();
    
    // Ensure we have the expected number of detectors
    let detector_count = scanner.get_detector_count();
    assert!(detector_count >= 10, "Should have at least 10 detectors registered");
    
    // Test specific detector existence
    assert!(scanner.has_detector("access_control"), "Should have access_control detector");
    assert!(scanner.has_detector("reentrancy"), "Should have reentrancy detector");
    assert!(scanner.has_detector("input_validation"), "Should have input_validation detector");
}

#[test]
fn test_confidence_filtering() {
    let scanner = Scanner::new();
    
    // Create a test file with potential low-confidence findings
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(
        temp_file,
        r#"
contract TestContract {{
    fn helper_function() {{
        let magic_number = 42; // This might be a low-confidence magic number
    }}
}}
        "#
    ).unwrap();
    
    let file_path = temp_file.path().to_path_buf();
    let content = std::fs::read_to_string(&file_path).unwrap();
    
    let sway_file = SwayFile {
        path: file_path,
        content,
    };
    
    let findings = scanner.analyze_file(&sway_file).unwrap();
    
    // Filter by confidence
    let high_confidence_findings: Vec<_> = findings.iter()
        .filter(|f| f.confidence >= 0.8)
        .collect();
    
    let low_confidence_findings: Vec<_> = findings.iter()
        .filter(|f| f.confidence < 0.5)
        .collect();
    
    // Should be able to distinguish confidence levels
    assert!(
        high_confidence_findings.len() != findings.len() || findings.is_empty(),
        "Should have varied confidence levels in findings"
    );
}

#[test]
fn test_empty_file_handling() {
    let scanner = Scanner::new();
    
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "// Empty contract file").unwrap();
    
    let file_path = temp_file.path().to_path_buf();
    let content = std::fs::read_to_string(&file_path).unwrap();
    
    let sway_file = SwayFile {
        path: file_path,
        content,
    };
    
    // Should handle empty files gracefully
    let result = scanner.analyze_file(&sway_file);
    assert!(result.is_ok(), "Should handle empty files without errors");
    
    let findings = result.unwrap();
    assert!(findings.is_empty(), "Empty file should produce no findings");
} 