// Example Vulnerable Contract for SwayScanner
// This file demonstrates various security vulnerabilities that SwayScanner can detect
//
// USAGE:
// Run SwayScanner on this file to see vulnerability detection in action:
//   swayscan examples/vulnerable_contract.sw --export-md
//   
// This example contains intentional vulnerabilities including:
//   - Access control issues
//   - Input validation problems  
//   - Reentrancy vulnerabilities
//   - Oracle manipulation risks
//   - Business logic flaws
//   - Cryptographic weaknesses
//
// For more information visit: https://safeedges.in

contract TestContract {
    storage {
        balances: StorageMap<Identity, u64> = StorageMap {},
        total_supply: u64 = 0,
        owner: Identity = Identity::Address(Address::zero()),
        paused: bool = false,
        oracle_prices: StorageMap<AssetId, u64> = StorageMap {},
        flash_loans: StorageMap<Identity, u64> = StorageMap {},
    }
}

abi TestContract {
    // TEST 1: PROPERLY VALIDATED FUNCTION (should NOT trigger)
    #[storage(read, write)]
    fn secure_transfer(to: Identity, amount: u64);
    
    // TEST 2: UNVALIDATED FINANCIAL FUNCTION (should trigger high severity)
    #[storage(read, write)]
    fn unsafe_withdraw(amount: u64);
    
    // TEST 3: ACCESS CONTROL TESTS
    #[storage(read, write)]
    fn admin_mint(to: Identity, amount: u64); // No access control - should trigger
    
    #[storage(read, write)]
    fn secure_admin_function(amount: u64); // Has access control - should NOT trigger
    
    // TEST 4: ORACLE MANIPULATION TESTS
    #[storage(read, write)]
    fn vulnerable_price_update(asset: AssetId, price: u64); // Single oracle - should trigger
    
    #[storage(read, write)]
    fn secure_price_update(asset: AssetId, price1: u64, price2: u64, price3: u64); // Multiple sources - should NOT trigger
    
    // TEST 5: REENTRANCY TESTS
    #[storage(read, write)]
    fn vulnerable_callback(user: Identity, amount: u64); // External call first - should trigger
    
    #[storage(read, write)]
    fn secure_withdrawal(amount: u64); // Checks-Effects-Interactions - should NOT trigger
    
    // TEST 6: BUSINESS LOGIC TESTS
    #[storage(read, write)]
    fn risky_liquidation(user: Identity, asset: AssetId); // Complex logic - should trigger
    
    // TEST 7: VIEW FUNCTIONS (should NOT trigger any detectors)
    #[storage(read)]
    fn get_balance(user: Identity) -> u64;
    
    #[storage(read)]
    fn total_supply() -> u64;
    
    // TEST 8: CRYPTOGRAPHIC TESTS
    fn weak_random_generator() -> u64; // Timestamp-based - should trigger
    
    fn secure_random_with_oracle() -> u64; // Uses multiple sources - should NOT trigger
}

impl TestContract for Contract {
    
    // TEST 1: PROPERLY VALIDATED FUNCTION
    #[storage(read, write)]
    fn secure_transfer(to: Identity, amount: u64) {
        // GOOD: Comprehensive validation
        require(amount > 0, "Amount must be positive");
        require(amount <= 1000000000, "Amount too large");
        
        match to {
            Identity::Address(addr) => {
                require(addr != Address::zero(), "Zero address not allowed");
            },
            _ => {}
        }
        
        let caller = msg_sender().unwrap();
        let balance = storage.balances.get(caller).try_read().unwrap_or(0);
        require(balance >= amount, "Insufficient balance");
        
        // GOOD: State changes before external calls
        storage.balances.insert(caller, balance - amount);
        storage.balances.insert(to, storage.balances.get(to).try_read().unwrap_or(0) + amount);
        
        // GOOD: External call last
        transfer(to, AssetId::base(), amount);
    }
    
    // TEST 2: UNVALIDATED FINANCIAL FUNCTION
    #[storage(read, write)]
    fn unsafe_withdraw(amount: u64) {
        let caller = msg_sender().unwrap();
        
        // BAD: No amount validation
        // BAD: No balance check
        // BAD: External call before state change (reentrancy)
        transfer(caller, AssetId::base(), amount);
        
        let balance = storage.balances.get(caller).try_read().unwrap_or(0);
        storage.balances.insert(caller, balance - amount); // Can underflow
    }
    
    // TEST 3: ACCESS CONTROL - MISSING
    #[storage(read, write)]
    fn admin_mint(to: Identity, amount: u64) {
        // BAD: No access control check
        // BAD: No input validation
        
        let current_supply = storage.total_supply.read();
        storage.total_supply.write(current_supply + amount); // Can overflow
        
        let balance = storage.balances.get(to).try_read().unwrap_or(0);
        storage.balances.insert(to, balance + amount);
        
        mint_to(to, AssetId::base(), amount);
    }
    
    // TEST 3: ACCESS CONTROL - SECURE
    #[storage(read, write)]
    fn secure_admin_function(amount: u64) {
        // GOOD: Access control check
        require(msg_sender().unwrap() == storage.owner.read(), "Only owner");
        
        // GOOD: Input validation
        require(amount > 0, "Amount must be positive");
        require(amount <= 1000000, "Amount too large");
        
        storage.total_supply.write(storage.total_supply.read() + amount);
    }
    
    // TEST 4: ORACLE MANIPULATION - VULNERABLE
    #[storage(read, write)]
    fn vulnerable_price_update(asset: AssetId, price: u64) {
        // BAD: Single oracle source
        // BAD: No price validation
        // BAD: No staleness check
        
        storage.oracle_prices.insert(asset, price);
        
        // BAD: Using price immediately without validation
        if price > 1000000 {
            let bonus = price * 100; // Price manipulation can affect this
            storage.total_supply.write(storage.total_supply.read() + bonus);
        }
    }
    
    // TEST 4: ORACLE MANIPULATION - SECURE
    #[storage(read, write)]
    fn secure_price_update(asset: AssetId, price1: u64, price2: u64, price3: u64) {
        // GOOD: Multiple price sources
        require(price1 > 0 && price2 > 0 && price3 > 0, "Invalid prices");
        
        // GOOD: Price deviation check
        let avg_price = (price1 + price2 + price3) / 3;
        require(
            (price1 <= avg_price * 110 / 100) && (price1 >= avg_price * 90 / 100),
            "Price1 deviation too high"
        );
        require(
            (price2 <= avg_price * 110 / 100) && (price2 >= avg_price * 90 / 100),
            "Price2 deviation too high"
        );
        
        storage.oracle_prices.insert(asset, avg_price);
    }
    
    // TEST 5: REENTRANCY - VULNERABLE
    #[storage(read, write)]
    fn vulnerable_callback(user: Identity, amount: u64) {
        // BAD: External call before state change
        transfer(user, AssetId::base(), amount);
        
        // BAD: State change after external call
        let balance = storage.balances.get(user).try_read().unwrap_or(0);
        storage.balances.insert(user, balance - amount);
    }
    
    // TEST 5: REENTRANCY - SECURE
    #[storage(read, write)]
    fn secure_withdrawal(amount: u64) {
        let caller = msg_sender().unwrap();
        
        // GOOD: Checks first
        require(amount > 0, "Amount must be positive");
        let balance = storage.balances.get(caller).try_read().unwrap_or(0);
        require(balance >= amount, "Insufficient balance");
        
        // GOOD: Effects (state changes) second
        storage.balances.insert(caller, balance - amount);
        
        // GOOD: Interactions (external calls) last
        transfer(caller, AssetId::base(), amount);
    }
    
    // TEST 6: BUSINESS LOGIC - VULNERABLE
    #[storage(read, write)]
    fn risky_liquidation(user: Identity, asset: AssetId) {
        let price = storage.oracle_prices.get(asset).try_read().unwrap_or(0);
        let collateral = storage.balances.get(user).try_read().unwrap_or(0);
        
        // BAD: Hardcoded liquidation threshold (magic number)
        // BAD: Direct price usage without staleness check
        // BAD: No slippage protection
        if collateral * price < 150000000 { // Magic number
            // BAD: Force liquidation without proper validation
            storage.balances.insert(user, 0);
            
            // BAD: External call in conditional logic
            transfer(msg_sender().unwrap(), asset, collateral);
        }
    }
    
    // TEST 7: VIEW FUNCTIONS - SAFE
    #[storage(read)]
    fn get_balance(user: Identity) -> u64 {
        storage.balances.get(user).try_read().unwrap_or(0)
    }
    
    #[storage(read)]
    fn total_supply() -> u64 {
        storage.total_supply.read()
    }
    
    // TEST 8: CRYPTOGRAPHIC - WEAK
    fn weak_random_generator() -> u64 {
        // BAD: Using timestamp for randomness
        let timestamp = std::block::timestamp();
        let sender_bytes = std::tx::tx_id();
        
        // BAD: Predictable randomness source
        keccak256((timestamp, sender_bytes)) % 1000000
    }
    
    // TEST 8: CRYPTOGRAPHIC - BETTER
    fn secure_random_with_oracle() -> u64 {
        // BETTER: Using multiple unpredictable sources
        let tx_id = std::tx::tx_id();
        let block_height = std::block::height();
        let gas_limit = std::tx::gas_limit();
        
        // BETTER: Combining multiple sources
        keccak256((tx_id, block_height, gas_limit)) % 1000000
    }
}

// TEST 9: HELPER FUNCTIONS (should mostly be ignored)
fn test_helper_function() {
    // This is a helper function, should not trigger many detectors
    let amount = 1000000; // This magic number is acceptable in helpers
}

#[test]
fn test_contract_functions() {
    // Test functions should not trigger detectors
    let test_amount = 42; // Acceptable in tests
    let test_address = Address::from(0x1234567890123456789012345678901234567890123456789012345678901234);
}

// TEST 10: EDGE CASES
contract EdgeCaseContract {
    storage {
        data: u64 = 0,
    }
}

abi EdgeCaseContract {
    // Should NOT trigger - read-only function with parameter
    #[storage(read)]
    fn safe_read_function(id: u64) -> u64;
    
    // Should trigger - write function without validation
    #[storage(write)]
    fn unsafe_write_function(value: u64);
}

impl EdgeCaseContract for Contract {
    #[storage(read)]
    fn safe_read_function(id: u64) -> u64 {
        // This should NOT trigger input validation warnings
        // because it's read-only and doesn't perform risky operations
        storage.data.read() + id
    }
    
    #[storage(write)]
    fn unsafe_write_function(value: u64) {
        // This SHOULD trigger because it writes to storage without validation
        storage.data.write(value);
    }
} 