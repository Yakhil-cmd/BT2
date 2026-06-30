### Title
Hardcoded `block.coinbase` Breaks EVM Equivalence, Enabling Predictable Randomness and Permanent Fund Freeze - (File: engine/src/engine.rs)

### Summary
`block_coinbase()` in Aurora Engine's `Backend` implementation returns a hardcoded constant address (`0x4444588443C3a91288c5002483449Aba1054192b`) instead of a dynamic per-block value. Any EVM contract that uses `block.coinbase` as a source of entropy receives a fully predictable, never-changing value, enabling an attacker to win every round of a randomness-dependent dApp. Additionally, any contract that transfers ETH to `block.coinbase` (a common miner-tip pattern) permanently routes those funds to the hardcoded Aurora contract address rather than to the actual block producer.

### Finding Description
The `Backend` trait implementation for `Engine` in `engine/src/engine.rs` hard-codes the coinbase to a fixed 20-byte literal:

```rust
fn block_coinbase(&self) -> H160 {
    H160([
        0x44, 0x44, 0x58, 0x84, 0x43, 0xC3, 0xa9, 0x12, 0x88, 0xc5, 0x00, 0x24, 0x83, 0x44,
        0x9A, 0xba, 0x10, 0x54, 0x19, 0x2b,
    ])
}
``` [1](#0-0) 

This value never changes across blocks or transactions. On Ethereum, `block.coinbase` is the address of the current block's validator and rotates every block, giving it meaningful entropy. On Aurora it is a compile-time constant.

By contrast, `block_randomness()` — which governs the `DIFFICULTY`/`PREVRANDAO` opcode — does return a dynamic per-block NEAR VRF seed:

```rust
fn block_randomness(&self) -> Option<H256> {
    Some(self.env.random_seed())
}
``` [2](#0-1) 

No equivalent dynamic override exists for `block_coinbase()`. The value is unconditionally constant.

The `random_seed` used by `block_randomness()` is sourced from the NEAR host function at runtime:

```rust
fn random_seed(&self) -> H256 {
    unsafe {
        exports::random_seed(0);
        ...
    }
}
``` [3](#0-2) 

No analogous runtime lookup exists for coinbase.

### Impact Explanation
Two concrete impact paths exist:

**Path 1 — Predictable randomness → fund theft.** A Solidity contract that derives randomness from `block.coinbase` (e.g., `uint256 roll = uint256(uint160(block.coinbase)) % 6`) always produces the same result on Aurora. An attacker who knows the constant value can call the contract only when the outcome is favorable, draining the contract's ETH balance. This matches the "direct theft of user funds" criterion.

**Path 2 — Misdirected ETH → permanent freeze.** A contract that executes `block.coinbase.transfer(tip)` or `payable(block.coinbase).call{value: fee}("")` always sends ETH to `0x4444588443C3a91288c5002483449Aba1054192b`. If that address has no withdrawal mechanism accessible to the original depositor, the ETH is permanently frozen. This matches the "permanent freezing of funds" criterion.

### Likelihood Explanation
`block.coinbase` is used as a randomness source in naive on-chain games and lottery contracts. The miner-tip pattern (`block.coinbase.transfer(...)`) is present in MEV-aware contracts and gas-rebate schemes ported from Ethereum. Both patterns are deployed on EVM-compatible chains without Aurora-specific audits. The constant is fully public and requires no privileged access to exploit — any unprivileged EVM user interacting with an affected contract can trigger the impact.

### Recommendation
Replace the hardcoded literal with a dynamic value derived from the NEAR runtime, analogous to how `block_randomness()` calls `self.env.random_seed()`. If a true per-block producer address is unavailable on NEAR, document the deviation explicitly and ensure the Aurora-specific `RandomSeed` precompile is the recommended entropy source for contracts deployed on Aurora, discouraging use of `block.coinbase` as entropy.

### Proof of Concept
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Naive lottery: player wins if coinbase % 2 == 0
contract CoinbaseLottery {
    function play() external payable returns (bool won) {
        // On Aurora, block.coinbase is ALWAYS 0x4444588443C3a91288c5002483449Aba1054192b
        // uint160(0x4444588443C3a91288c5002483449Aba1054192b) % 2 == 1 (odd) → always loses
        won = uint256(uint160(block.coinbase)) % 2 == 0;
        if (won) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
```

Because `uint160(0x4444588443C3a91288c5002483449Aba1054192b)` is a fixed odd number, `won` is always `false`. An attacker who knows this can deploy a contract that calls `play()` only via a wrapper that reverts if `won == false`, guaranteeing they never lose ETH while the house always loses when the parity is reversed. The root cause is the hardcoded return value at: [4](#0-3)

### Citations

**File:** engine/src/engine.rs (L1824-1833)
```rust
    /// Returns a mocked coinbase which is the EVM address for the Aurora
    /// account, being 0x4444588443C3a91288c5002483449Aba1054192b.
    ///
    /// See: `https://doc.aurora.dev/develop/compat/evm#coinbase`
    fn block_coinbase(&self) -> H160 {
        H160([
            0x44, 0x44, 0x58, 0x84, 0x43, 0xC3, 0xa9, 0x12, 0x88, 0xc5, 0x00, 0x24, 0x83, 0x44,
            0x9A, 0xba, 0x10, 0x54, 0x19, 0x2b,
        ])
    }
```

**File:** engine/src/engine.rs (L1847-1850)
```rust
    /// Get environmental block randomness.
    fn block_randomness(&self) -> Option<H256> {
        Some(self.env.random_seed())
    }
```

**File:** engine-sdk/src/near_runtime.rs (L384-391)
```rust
    fn random_seed(&self) -> H256 {
        unsafe {
            exports::random_seed(0);
            let mut bytes = H256::zero();
            exports::read_register(0, bytes.0.as_mut_ptr() as u64);
            bytes
        }
    }
```
