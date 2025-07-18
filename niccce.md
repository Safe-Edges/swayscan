# 🛡️ Security Audit Report

## 📋 Project Information

| Field | Value |
|-------|-------|
| **Project Name** | Sway Smart Contract |
| **Audit Date** | July 18, 2025 |
| **Total Issues Found** | 10 |
| **Auditor** | Safe Edges Security |
| **Report Version** | 1.0 |

---

## 📊 Executive Summary

⚠️ **CRITICAL ATTENTION REQUIRED** - High or Critical severity vulnerabilities detected.

### Risk Level Distribution

| Severity | Count | Risk Level |
|----------|-------|------------|
| 🔴 **Critical** | 1 | Immediate action required |
| 🟠 **High** | 6 | Priority fix needed |
| 🟡 **Medium** | 3 | Should be addressed |

---

## 📈 Analysis Statistics

### Issues by Category

| Category | Count | Percentage |
|----------|-------|------------|
| 🔒 Security | 10 | 100% |

### Top Detectors

| Detector | Issues Found |
|----------|-------------|
| `data_validation` | 4 |
| `unchecked_external_calls` | 1 |
| `cryptographic_issues` | 1 |
| `input_validation` | 1 |
| `reentrancy_vulnerability` | 1 |

---

## 🔍 Findings by Severity

### 🔴 Critical Severity (1 issues)

- **Potential Reentrancy Vulnerability (5 occurrences)** in `test_reentrancy.sw:33` - External call at line 33 may allow reentrancy attack. State changes detected after external call: Line 36: storage.balances.insert(. This pattern can allow an attacker to call back into the contract before state changes are finalized.

### 🟠 High Severity (6 issues)

- **Unprotected Storage Modification (9 occurrences)** in `test_access_control.sw:31` - Storage variable is modified without proper access control
- **Insufficient Input Validation (7 occurrences)** in `test_reentrancy.sw:57` - Function at line 57 accepts parameters fn guarded_withdraw(amount: u64) but performs dangerous operations without sufficient validation: storage write, transfer, storage write. Risk factors: Financial operation context, High-risk operations present, Missing input bounds validation, Missing overflow protection. Unvalidated inputs can lead to vulnerabilities.
- **External Call in Loop (5 occurrences)** in `test_reentrancy.sw:32` - Loop containing external calls detected. This pattern can lead to gas exhaustion, reentrancy attacks, or DoS conditions.
- **Missing Input Validation (5 occurrences)** in `test_reentrancy.sw:57` - Function parameter 'fn guarded_withdraw(amount: u64' is used in security-critical operations without proper validation. This could lead to unexpected behavior or vulnerabilities.
- **Unchecked External Call** in `vulnerable_contract.sw:32` - Asset transfer at line 32 does not check return value or handle potential failures. Call: 'transfer(to: Identity, amount: u64);'. Risk factors: High-risk financial operation, Financial context. Failed external calls can cause unexpected behavior or loss of funds.
- **Insecure Randomness Source** in `vulnerable_contract.sw:241` - Using predictable or weak randomness source: timestamp for rand. This can lead to predictable outcomes in security-critical operations.

### 🟡 Medium Severity (3 issues)

- **Missing Bounds Checking (25 occurrences)** in `test_access_control.sw:33` - Array or collection access 'get(to)' without bounds checking. This could lead to out-of-bounds access or panic conditions.
- **Missing Zero Address Check (6 occurrences)** in `test_access_control.sw:53` - Operation using address parameter without checking for zero address. This could lead to permanent loss of assets.
- **Missing Zero Amount Check (2 occurrences)** in `vulnerable_contract.sw:32` - Transfer operation without checking for zero amount. This wastes gas and may indicate logical errors.

---

## 📝 Detailed Findings

### 🔴 Potential Reentrancy Vulnerability (5 occurrences)

**Severity:** Critical | **Category:** Security | **Confidence:** 100.0%

**Location:** `test_reentrancy.sw:33:1`

**Description:**
External call at line 33 may allow reentrancy attack. State changes detected after external call: Line 36: storage.balances.insert(. This pattern can allow an attacker to call back into the contract before state changes are finalized.

Found in 5 locations:
  • test_reentrancy.sw:33 - 30:     require(balance >= amount, "Insufficient balance");
  • test_reentrancy.sw:83 - 80:     require(balance >= amount * 2, "Insufficient balance");
  • test_reentrancy.sw:84 - 81:
  • vulnerable_contract.sw:112 - 109:         // BAD: No amount validation
  • vulnerable_contract.sw:186 - 183:     #[storage(read, write)]

**Code:**
```rust
    30:     require(balance >= amount, "Insufficient balance");
    31:     
    32:     // VULNERABLE: External call before state update
>>> 33:     transfer(Identity::Address(sender), AssetId::base(), amount);
    34:     
    35:     // VULNERABLE: State change after external call
    36:     storage.balances.insert(sender, balance - amount);
```

**Recommendation:**
Implement the checks-effects-interactions pattern: (1) Perform all checks, (2) Make state changes, (3) Interact with external contracts. Consider using a reentrancy guard or mutex.

---

### 🟠 Unprotected Storage Modification (9 occurrences)

**Severity:** High | **Category:** Security | **Confidence:** 80.0%

**Location:** `test_access_control.sw:31:1`

**Description:**
Storage variable is modified without proper access control

Found in 9 locations:
  • test_access_control.sw:31 - 29:     // VULNERABLE: No access control check
  • test_access_control.sw:45 - 43:
  • test_access_control.sw:64 - 62:
  • test_reentrancy.sw:60 - 58:     // SECURE: Reentrancy guard
  • test_reentrancy.sw:71 - 69:
  • vulnerable_contract.sw:125 - 123:
  • vulnerable_contract.sw:143 - 141:         require(amount <= 1000000, "Amount too large");
  • vulnerable_contract.sw:158 - 156:         if price > 1000000 {
  • vulnerable_contract.sw:302 - 300:     fn unsafe_write_function(value: u64) {

**Code:**
```rust
    29:     // VULNERABLE: No access control check
    30:     let current_supply = storage.total_supply.read();
>>> 31:     storage.total_supply.write(current_supply + amount);
    32:     
    33:     let balance = storage.balances.get(to).try_read().unwrap_or(0);
```

**Recommendation:**
Add access control checks before modifying storage variables

---

### 🟠 Insufficient Input Validation (7 occurrences)

**Severity:** High | **Category:** Security | **Confidence:** 99.2%

**Location:** `test_reentrancy.sw:57:0`

**Description:**
Function at line 57 accepts parameters fn guarded_withdraw(amount: u64) but performs dangerous operations without sufficient validation: storage write, transfer, storage write. Risk factors: Financial operation context, High-risk operations present, Missing input bounds validation, Missing overflow protection. Unvalidated inputs can lead to vulnerabilities.

Found in 7 locations:
  • test_reentrancy.sw:57 - 54:
  • test_reentrancy.sw:76 - 73:
  • test_reentrancy.sw:76 - 73:
  • test_reentrancy.sw:92 - 89:
  • vulnerable_contract.sw:184 - 181:
  • vulnerable_contract.sw:184 - 181:
  • vulnerable_contract.sw:300 - 297:     }

**Code:**
```rust
    54: 
    55: // TEST 3: Reentrancy guard pattern - SHOULD NOT be flagged
    56: #[storage(read, write)]
>>> 57: fn guarded_withdraw(amount: u64) {
    58:     // SECURE: Reentrancy guard
    59:     require(!storage.locked.read(), "Reentrant call");
    60:     storage.locked.write(true);
```

**Recommendation:**
Implement comprehensive input validation: (1) Add require() statements for parameter bounds, (2) Check for zero addresses/IDs, (3) Validate ranges before arithmetic operations, (4) Use checked arithmetic for financial calculations, (5) Add parameter sanitization for arrays/loops.

---

### 🟠 External Call in Loop (5 occurrences)

**Severity:** High | **Category:** Security | **Confidence:** 85.0%

**Location:** `test_reentrancy.sw:32:0`

**Description:**
Loop containing external calls detected. This pattern can lead to gas exhaustion, reentrancy attacks, or DoS conditions.

Found in 5 locations:
  • test_reentrancy.sw:32 - 30:     require(balance >= amount, "Insufficient balance");
  • test_reentrancy.sw:82 - 80:     require(balance >= amount * 2, "Insufficient balance");
  • vulnerable_contract.sw:96 - 94:         require(balance >= amount, "Insufficient balance");
  • vulnerable_contract.sw:111 - 109:         // BAD: No amount validation
  • vulnerable_contract.sw:185 - 183:     #[storage(read, write)]

**Code:**
```rust
    30:     require(balance >= amount, "Insufficient balance");
    31:     
>>> 32:     // VULNERABLE: External call before state update
    33:     transfer(Identity::Address(sender), AssetId::base(), amount);
    34:     
```

**Recommendation:**
Avoid external calls in loops. Use pull-over-push pattern, batch operations, or implement proper gas limits and bounds checking.

---

### 🟠 Missing Input Validation (5 occurrences)

**Severity:** High | **Category:** Security | **Confidence:** 84.0%

**Location:** `test_reentrancy.sw:57:0`

**Description:**
Function parameter 'fn guarded_withdraw(amount: u64' is used in security-critical operations without proper validation. This could lead to unexpected behavior or vulnerabilities.

Found in 5 locations:
  • test_reentrancy.sw:57 - 54:
  • test_reentrancy.sw:76 - 73:
  • test_reentrancy.sw:76 - 73:
  • vulnerable_contract.sw:184 - 181:
  • vulnerable_contract.sw:300 - 297:     }

**Code:**
```rust
    54: 
    55: // TEST 3: Reentrancy guard pattern - SHOULD NOT be flagged
    56: #[storage(read, write)]
>>> 57: fn guarded_withdraw(amount: u64) {
    58:     // SECURE: Reentrancy guard
    59:     require(!storage.locked.read(), "Reentrant call");
    60:     storage.locked.write(true);
```

**Recommendation:**
Add input validation using require() statements to check parameter bounds, non-zero values, valid addresses, and other constraints before using parameters in critical operations.

---

### 🟠 Unchecked External Call

**Severity:** High | **Category:** Security | **Confidence:** 100.0%

**Location:** `vulnerable_contract.sw:32:1`

**Description:**
Asset transfer at line 32 does not check return value or handle potential failures. Call: 'transfer(to: Identity, amount: u64);'. Risk factors: High-risk financial operation, Financial context. Failed external calls can cause unexpected behavior or loss of funds.

**Code:**
```rust
    30:     // TEST 1: PROPERLY VALIDATED FUNCTION (should NOT trigger)
    31:     #[storage(read, write)]
>>> 32:     fn secure_transfer(to: Identity, amount: u64);
    33:     
    34:     // TEST 2: UNVALIDATED FINANCIAL FUNCTION (should trigger high severity)
```

**Recommendation:**
Handle external call results properly: (1) Assign return value and check for success, (2) Use match statement for Result types, (3) Add require() or assert() for critical calls, (4) Consider using try-catch equivalent patterns. Example: let result = transfer(...); require(result.is_ok(), "Call failed");

---

### 🟠 Insecure Randomness Source

**Severity:** High | **Category:** Security | **Confidence:** 85.0%

**Location:** `vulnerable_contract.sw:241:22`

**Description:**
Using predictable or weak randomness source: timestamp for rand. This can lead to predictable outcomes in security-critical operations.

**Code:**
```rust
    239:     // TEST 8: CRYPTOGRAPHIC - WEAK
    240:     fn weak_random_generator() -> u64 {
>>> 241:         // BAD: Using timestamp for randomness
    242:         let timestamp = std::block::timestamp();
    243:         let sender_bytes = std::tx::tx_id();
```

**Recommendation:**
Use a cryptographically secure random number generator (CSPRNG) or commit-reveal schemes for randomness in smart contracts.

---

### 🟡 Missing Bounds Checking (25 occurrences)

**Severity:** Medium | **Category:** Security | **Confidence:** 80.0%

**Location:** `test_access_control.sw:33:35`

**Description:**
Array or collection access 'get(to)' without bounds checking. This could lead to out-of-bounds access or panic conditions.

Found in 25 locations:
  • test_access_control.sw:33 - 31:     storage.total_supply.write(current_supply + amount);
  • test_access_control.sw:34 - 32:
  • test_access_control.sw:47 - 45:     storage.total_supply.write(current_supply + amount);
  • test_access_control.sw:48 - 46:
  • test_access_control.sw:71 - 69: fn get_balance(user: Address) -> u64 {
  • test_reentrancy.sw:36 - 34:
  • test_reentrancy.sw:49 - 47:
  • test_reentrancy.sw:87 - 85:
  • test_reentrancy.sw:94 - 92: fn safe_balance_check(user: Address) -> u64 {
  • vulnerable_contract.sw:97 - 95:
  • vulnerable_contract.sw:98 - 96:         // GOOD: State changes before external calls
  • vulnerable_contract.sw:98 - 96:         // GOOD: State changes before external calls
  • vulnerable_contract.sw:114 - 112:         transfer(caller, AssetId::base(), amount);
  • vulnerable_contract.sw:115 - 113:
  • vulnerable_contract.sw:127 - 125:         storage.total_supply.write(current_supply + amount); // Can overflow
  • vulnerable_contract.sw:128 - 126:
  • vulnerable_contract.sw:153 - 151:         // BAD: No staleness check
  • vulnerable_contract.sw:179 - 177:         );
  • vulnerable_contract.sw:189 - 187:
  • vulnerable_contract.sw:190 - 188:         // BAD: State change after external call
  • vulnerable_contract.sw:204 - 202:
  • vulnerable_contract.sw:213 - 211:     #[storage(read, write)]
  • vulnerable_contract.sw:214 - 212:     fn risky_liquidation(user: Identity, asset: AssetId) {
  • vulnerable_contract.sw:221 - 219:         if collateral * price < 150000000 { // Magic number
  • vulnerable_contract.sw:231 - 229:     #[storage(read)]

**Code:**
```rust
    31:     storage.total_supply.write(current_supply + amount);
    32:     
>>> 33:     let balance = storage.balances.get(to).try_read().unwrap_or(0);
    34:     storage.balances.insert(to, balance + amount);
    35: }
```

**Recommendation:**
Add bounds checking before array access using length checks or use safe access methods that return Option types.

---

### 🟡 Missing Zero Address Check (6 occurrences)

**Severity:** Medium | **Category:** Security | **Confidence:** 75.0%

**Location:** `test_access_control.sw:53:0`

**Description:**
Operation using address parameter without checking for zero address. This could lead to permanent loss of assets.

Found in 6 locations:
  • test_access_control.sw:53 - 51: // TEST 3: Admin access control - SHOULD NOT be flagged
  • test_reentrancy.sw:33 - 31:
  • test_reentrancy.sw:52 - 50:
  • test_reentrancy.sw:68 - 66:
  • test_reentrancy.sw:83 - 81:
  • test_reentrancy.sw:84 - 82:     // VULNERABLE: External calls before state update

**Code:**
```rust
    51: // TEST 3: Admin access control - SHOULD NOT be flagged
    52: #[storage(read, write)]  
>>> 53: fn secure_admin_burn(from: Address, amount: u64) {
    54:     // SECURE: Admin check
    55:     let sender = msg_sender().unwrap().as_address().unwrap();
```

**Recommendation:**
Add require(address != Address::zero()) to prevent operations with zero addresses.

---

### 🟡 Missing Zero Amount Check (2 occurrences)

**Severity:** Medium | **Category:** Security | **Confidence:** 85.0%

**Location:** `vulnerable_contract.sw:32:14`

**Description:**
Transfer operation without checking for zero amount. This wastes gas and may indicate logical errors.

Found in 2 locations:
  • vulnerable_contract.sw:32 - 30:     // TEST 1: PROPERLY VALIDATED FUNCTION (should NOT trigger)
  • vulnerable_contract.sw:80 - 78:     // TEST 1: PROPERLY VALIDATED FUNCTION

**Code:**
```rust
    30:     // TEST 1: PROPERLY VALIDATED FUNCTION (should NOT trigger)
    31:     #[storage(read, write)]
>>> 32:     fn secure_transfer(to: Identity, amount: u64);
    33:     
    34:     // TEST 2: UNVALIDATED FINANCIAL FUNCTION (should trigger high severity)
```

**Recommendation:**
Add require(amount > 0) before transfer operations to prevent zero-value transfers.

## 💡 General Recommendations

### Immediate Actions

🚨 **URGENT:** Address all Critical severity issues immediately before deployment.

🔥 **HIGH PRIORITY:** Resolve High severity vulnerabilities as soon as possible.

### Security Best Practices

1. **Access Control:** Implement proper access control checks for all privileged functions
2. **Input Validation:** Validate all user inputs with appropriate bounds checking
3. **Reentrancy Protection:** Follow checks-effects-interactions pattern
4. **UTXO Validation:** Implement proper UTXO double-spend protection
5. **Oracle Security:** Use multiple price feeds with deviation checks
6. **Error Handling:** Properly handle all external call failures

### Code Quality

- Add comprehensive unit tests for all functions
- Implement integration tests for complex workflows
- Add proper documentation and comments
- Consider formal verification for critical components

---

## 📞 Contact Information

**Safe Edges Security**
- Website: [safeedges.in](https://safeedges.in)
- Email: security@safeedges.in
- Specialized in Sway and Fuel ecosystem security

---

*This report was generated by SwayScanner v0.2.3 on 2025-07-18 16:00:21 UTC*

**Disclaimer:** This audit report is provided for informational purposes only and does not guarantee the security of the audited smart contract. The auditors have made every effort to identify potential vulnerabilities, but cannot guarantee that all issues have been found. The final responsibility for security lies with the development team.
