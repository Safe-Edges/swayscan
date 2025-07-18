// Access Control Test Cases for SwayScanner
// This file contains various access control patterns for testing the access control detector
//
// USAGE: swayscan examples/test_access_control.sw

contract;

use std::{
    auth::msg_sender,
    storage::storage_api::{read, write},
    asset::*,
    address::Address,
};

storage {
    owner: Address = Address::zero(),
    admin: Address = Address::zero(),
    total_supply: u64 = 0,
    balances: StorageMap<Address, u64> = StorageMap {},
}

// ============================================================================
// ACCESS CONTROL TEST CASES
// ============================================================================

// TEST 1: Missing access control - SHOULD be flagged
#[storage(read, write)]
fn vulnerable_mint(to: Address, amount: u64) {
    // VULNERABLE: No access control check
    let current_supply = storage.total_supply.read();
    storage.total_supply.write(current_supply + amount);
    
    let balance = storage.balances.get(to).try_read().unwrap_or(0);
    storage.balances.insert(to, balance + amount);
}

// TEST 2: Proper owner-only access control - SHOULD NOT be flagged
#[storage(read, write)]
fn secure_owner_mint(to: Address, amount: u64) {
    // SECURE: Owner check
    let sender = msg_sender().unwrap().as_address().unwrap();
    require(sender == storage.owner.read(), "Only owner can mint");
    
    let current_supply = storage.total_supply.read();
    storage.total_supply.write(current_supply + amount);
    
    let balance = storage.balances.get(to).try_read().unwrap_or(0);
    storage.balances.insert(to, balance + amount);
}

// TEST 3: Admin access control - SHOULD NOT be flagged
#[storage(read, write)]  
fn secure_admin_burn(from: Address, amount: u64) {
    // SECURE: Admin check
    let sender = msg_sender().unwrap().as_address().unwrap();
    require(sender == storage.admin.read() || sender == storage.owner.read(), "Only admin or owner");
    
    let balance = storage.balances.get(from).try_read().unwrap_or(0);
    require(balance >= amount, "Insufficient balance");
    
    storage.balances.insert(from, balance - amount);
    
    let current_supply = storage.total_supply.read();
    storage.total_supply.write(current_supply - amount);
}

// TEST 4: Public view function - SHOULD NOT be flagged
#[storage(read)]
fn get_balance(user: Address) -> u64 {
    // SECURE: Read-only operations don't need access control
    storage.balances.get(user).try_read().unwrap_or(0)
} 