// Reentrancy Vulnerability Test Cases for SwayScanner
// This file contains various reentrancy patterns for testing the reentrancy detector
//
// USAGE: swayscan examples/test_reentrancy.sw

contract;

use std::{
    auth::msg_sender,
    storage::storage_api::{read, write},
    asset::*,
    address::Address,
};

storage {
    balances: StorageMap<Address, u64> = StorageMap {},
    locked: bool = false,
}

// ============================================================================
// REENTRANCY TEST CASES - Advanced State Change Analysis
// ============================================================================

// TEST 1: Classic reentrancy vulnerability - SHOULD be flagged
#[storage(read, write)]
fn vulnerable_withdraw(amount: u64) {
    let sender = msg_sender().unwrap().as_address().unwrap();
    let balance = storage.balances.get(sender).try_read().unwrap_or(0);
    
    require(balance >= amount, "Insufficient balance");
    
    // VULNERABLE: External call before state update
    transfer(Identity::Address(sender), AssetId::base(), amount);
    
    // VULNERABLE: State change after external call
    storage.balances.insert(sender, balance - amount);
}

// TEST 2: Secure withdrawal using checks-effects-interactions - SHOULD NOT be flagged
#[storage(read, write)]
fn secure_withdraw(amount: u64) {
    let sender = msg_sender().unwrap().as_address().unwrap();
    let balance = storage.balances.get(sender).try_read().unwrap_or(0);
    
    // SECURE: Checks first
    require(balance >= amount, "Insufficient balance");
    
    // SECURE: Effects (state changes) second
    storage.balances.insert(sender, balance - amount);
    
    // SECURE: Interactions (external calls) last
    transfer(Identity::Address(sender), AssetId::base(), amount);
}

// TEST 3: Reentrancy guard pattern - SHOULD NOT be flagged
#[storage(read, write)]
fn guarded_withdraw(amount: u64) {
    // SECURE: Reentrancy guard
    require(!storage.locked.read(), "Reentrant call");
    storage.locked.write(true);
    
    let sender = msg_sender().unwrap().as_address().unwrap();
    let balance = storage.balances.get(sender).try_read().unwrap_or(0);
    
    require(balance >= amount, "Insufficient balance");
    
    storage.balances.insert(sender, balance - amount);
    transfer(Identity::Address(sender), AssetId::base(), amount);
    
    // SECURE: Reset guard after external call
    storage.locked.write(false);
}

// TEST 4: Multiple external calls with state changes - SHOULD be flagged
#[storage(read, write)]
fn vulnerable_multi_call(recipient1: Address, recipient2: Address, amount: u64) {
    let sender = msg_sender().unwrap().as_address().unwrap();
    let balance = storage.balances.get(sender).try_read().unwrap_or(0);
    
    require(balance >= amount * 2, "Insufficient balance");
    
    // VULNERABLE: External calls before state update
    transfer(Identity::Address(recipient1), AssetId::base(), amount);
    transfer(Identity::Address(recipient2), AssetId::base(), amount);
    
    
    // VULNERABLE: State change after external calls
    storage.balances.insert(sender, balance - (amount * 2));
}

// TEST 5: Read-only external call - SHOULD NOT be flagged
#[storage(read)]
fn safe_balance_check(user: Address) -> u64 {
    // SECURE: Read-only operations don't pose reentrancy risk
    storage.balances.get(user).try_read().unwrap_or(0)
} 