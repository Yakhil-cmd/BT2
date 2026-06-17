### Title
Unvalidated `reserved[1]` Refund Recipient in L1 Transactions Causes Bootloader Panic via `u256_to_b160_checked` - (`basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

### Summary

The ABI-encoded L1 transaction parser explicitly skips address validation for `reserved[1]` (the refund recipient field), marked with a `// TODO: validate address?` comment. When `process_l1_transaction` later passes this unvalidated U256 value to `u256_to_b160_checked`, the function uses a bare `assert!` to check that the upper 96 bits are zero. If `reserved[1]` contains any value with bits set above position 159, the `assert!` panics, crashing the bootloader. This violates the explicit design invariant that L1 transactions must never halt the chain regardless of their field values.

### Finding Description

**Root cause — missing validation in `validate_structure`:**

In `basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs` at lines 267–273, the structure validator for L1 and upgrade transactions explicitly defers address validation for `reserved[1]`:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
    _ => unreachable!(),
}
```

`reserved[1]` is parsed as a raw `U256` with no upper-bit check. [1](#0-0) 

**Panic path — `u256_to_b160_checked` uses `assert!`:**

In `zk_ee/src/utils/integer_utils.rs` at lines 133–143, the conversion function uses a bare `assert!`:

```rust
pub fn u256_to_b160_checked(src: U256) -> B160 {
    assert!(src.as_limbs()[3] == 0 && src.as_limbs()[2] < (1u64 << 32));
    ...
}
``` [2](#0-1) 

**Call site — unvalidated `reserved[1]` passed directly:**

In `process_l1_transaction.rs` at line 337, the raw `reserved[1]` value is passed to this function without any prior sanitization:

```rust
let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
``` [3](#0-2) 

**Design invariant violated:**

The codebase explicitly documents that L1 transactions cannot be invalidated and the bootloader must process them gracefully even when L1-side validation fails. The comment at lines 422–431 of `process_l1_transaction.rs` states:

> "L1 transactions cannot be invalidated. Therefore, the following function makes sure L1 transactions are processable even when some checks that should be performed by the L1 don't hold." [4](#0-3) 

The rest of the L1 processing code uses saturating arithmetic and logs for overflow cases. The `assert!` panic is inconsistent with this resilience design. `AGENTS.md` also explicitly states: "Panic paths reachable from untrusted input. ZKsync OS should not panic in production." [5](#0-4) 

**Exploit flow:**

1. Attacker (or a buggy/upgraded L1 bridge) submits an L1 priority transaction (`tx_type = 0x7F`) with `reserved[1]` set to a value with upper bits non-zero, e.g., `0x0001_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000`.
2. `validate_structure` accepts the transaction (the TODO branch does nothing).
3. `process_l1_transaction` reaches the refund step and calls `u256_to_b160_checked(reserved[1])`.
4. The `assert!` fires because `limbs[3] != 0`.
5. The bootloader panics — in forward mode this crashes the sequencer; in proving mode the RISC-V binary panics, making the block unprovable and halting finalization on L1.

### Impact Explanation

A single malformed L1 transaction causes the bootloader to panic unconditionally. In the proving path, the RISC-V binary panics, making the block unprovable. The chain cannot finalize the block on L1, resulting in a chain halt. In forward/sequencer mode, the sequencer process crashes. Both outcomes are critical: the chain is halted until the block is dropped or the software is patched.

### Likelihood Explanation

L1 transactions are submitted through L1 bridge contracts that currently validate the refund recipient as a 20-byte address. However:
- The ZKsync OS bootloader is explicitly designed to be resilient to malformed L1 transactions regardless of L1-side validation.
- A future upgrade to the L1 bridge, a bug in the bridge, or a direct submission path that bypasses bridge validation would expose this panic.
- The `// TODO: validate address?` comment confirms this was a known gap left unaddressed.
- The `assert!` macro (not a graceful error return) makes this a hard crash rather than a recoverable error.

### Recommendation

1. In `validate_structure` for `L1_L2_TX_TYPE` and `UPGRADE_TX_TYPE`, validate `reserved[1]` as a valid address (upper 96 bits must be zero), returning `Err(())` if invalid. Remove the `// TODO: validate address?` comment.
2. Replace the `assert!` in `u256_to_b160_checked` with a checked conversion that returns a `Result` or `Option`, and propagate the error gracefully through `process_l1_transaction` (consistent with how other L1 validation errors are handled via saturating arithmetic and logging).
3. Add a test case that submits an L1 transaction with `reserved[1]` having upper bits set and verifies the bootloader handles it without panicking.

### Proof of Concept

```rust
// In a test using L1TxBuilder / TestingFramework:
// Set reserved[1] (refund_recipient) to a value with upper bits set.
// The standard L1TxBuilder encodes refund_recipient as U256::from(U160::from(address)),
// so upper bits are always zero. To trigger the bug, directly encode a raw transaction
// with reserved[1] = 0x0001_0000_..._0000 (any value where limbs[3] != 0 or limbs[2] >= 2^32).

// Expected: bootloader panics at u256_to_b160_checked assert
// Actual (after fix): bootloader handles gracefully, transaction reverts or is skipped
```

The `validate_structure` function at line 270 has `// TODO: validate address?` confirming the gap. The `assert!` at line 134 of `integer_utils.rs` is the panic site. The call at line 337 of `process_l1_transaction.rs` is the reachable trigger. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L267-273)
```rust
        // reserved[1] = refund recipient for l1 to l2 and upgrade txs
        match tx_type {
            Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
                // TODO: validate address?
            }
            _ => unreachable!(),
        }
```

**File:** zk_ee/src/utils/integer_utils.rs (L133-143)
```rust
pub fn u256_to_b160_checked(src: U256) -> B160 {
    assert!(src.as_limbs()[3] == 0 && src.as_limbs()[2] < (1u64 << 32));
    let mut result = B160::ZERO;
    unsafe {
        result.as_limbs_mut()[0] = src.as_limbs()[0];
        result.as_limbs_mut()[1] = src.as_limbs()[1];
        result.as_limbs_mut()[2] = src.as_limbs()[2];
    }

    result
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L336-338)
```rust
    if to_refund_recipient > U256::ZERO {
        let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
        mint_base_token::<S, Config>(
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L422-431)
```rust
///
/// Compute and perform some checks on fee/resource parameters.
/// This function handles cases that for L2 transactions would be
/// validation errors, as "invalidating" an L1 transaction can halt
/// the chain (due to the priority queue).
/// Note that the "validation errors" are practically unreachable, as
/// gas_limit, gas_price and gas_per_pubdata are either checked or set
/// by the L1 contracts. We decide to handle these cases as a fallback in
/// case the L1 contracts aren't properly updated to reflect a change in
/// ZKsync OS.
```

**File:** AGENTS.md (L141-142)
```markdown
2. Panic paths reachable from untrusted input. ZKsync OS should not panic in production.
3. Edge cases reachable from malformed/external input.
```
