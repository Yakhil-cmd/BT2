### Title
Inverted Range Check in `block_number_in_range` Causes `get_block_hash` Syscall to Accept Out-of-Range Blocks and Reject Valid Ones - (File: `crates/blockifier/src/execution/syscalls/syscall_base.rs`)

### Summary

`block_number_in_range` in `syscall_base.rs` uses an inverted inequality (`<=`) to determine whether a requested block number falls within the range of stored block hashes. The condition returns `true` for blocks that are **too old** (outside the stored range) and `false` for blocks that are **within** the valid stored range. This is the direct Sequencer analog of the external report's inverted protection-period check: a boolean guard whose inequality direction is reversed, causing valid inputs to be denied and invalid inputs to be accepted.

### Finding Description

The function is documented as "Returns whether the given block number is within the range of stored block hashes relative to the current block number":

```rust
pub fn block_number_in_range(
    requested_block_number: BlockNumber,
    current_block_number: BlockNumber,
) -> bool {
    current_block_number
        .0
        .checked_sub(constants::STORED_BLOCK_HASH_BUFFER)
        .is_some_and(|oldest_allowed| requested_block_number.0 <= oldest_allowed)
}
``` [1](#0-0) 

The Starknet protocol stores block hashes for the window `[current − STORED_BLOCK_HASH_BUFFER, current − 1]`. A block number is **in range** when:

```
oldest_allowed  <=  requested  <  current
```

where `oldest_allowed = current − STORED_BLOCK_HASH_BUFFER`.

The implementation computes `oldest_allowed` correctly but then tests `requested_block_number.0 <= oldest_allowed`, which is the **opposite** direction. The result:

| Requested block | Correct "in range"? | `block_number_in_range` returns |
|---|---|---|
| `current − STORED_BLOCK_HASH_BUFFER` (oldest valid) | ✓ yes | `true` (boundary coincidence) |
| `current − STORED_BLOCK_HASH_BUFFER − 1` (too old) | ✗ no | `true` ← **wrong** |
| `current − STORED_BLOCK_HASH_BUFFER + 1` (valid) | ✓ yes | `false` ← **wrong** |
| `current − 1` (most recent valid) | ✓ yes | `false` ← **wrong** |

The function is consumed by the `get_block_hash` syscall handler in `syscall_base.rs` and by `snos_syscall_executor.rs`: [1](#0-0) 

Compare with `validate_proof_block_number`, which correctly uses `proof_block_number > max_allowed` to reject blocks that are too recent: [2](#0-1) 

The two functions address the same `STORED_BLOCK_HASH_BUFFER` window from opposite sides, but `block_number_in_range` has the inequality reversed.

### Impact Explanation

**Critical — Wrong syscall result from blockifier/syscall/execution logic for accepted input.**

When a contract executes `get_block_hash(n)` for any valid recent block `n` in `(current − STORED_BLOCK_HASH_BUFFER, current − 1]`, `block_number_in_range` returns `false`, so the syscall handler treats the request as out-of-range and either errors or returns a zero/sentinel value. Conversely, a request for a very old block (e.g., block 0) returns `true`, so the handler proceeds and reads storage that was never written, returning `Felt::ZERO` as the "hash." Any contract logic that branches on `get_block_hash` output — randomness, proof verification, replay protection — receives a corrupted value for valid inputs and a spuriously successful zero-hash for invalid inputs.

### Likelihood Explanation

Any deployed contract that calls the `get_block_hash` syscall with a recent block number (the overwhelmingly common case) will trigger this path. No special privileges or unusual inputs are required; a standard Invoke V3 transaction suffices. The bug is reachable through normal contract execution in the blockifier and through the OS-level syscall executor.

### Recommendation

Replace the inverted inequality with the correct lower-bound check and add the missing upper-bound check:

```rust
pub fn block_number_in_range(
    requested_block_number: BlockNumber,
    current_block_number: BlockNumber,
) -> bool {
    current_block_number
        .0
        .checked_sub(constants::STORED_BLOCK_HASH_BUFFER)
        .is_some_and(|oldest_allowed| {
            requested_block_number.0 >= oldest_allowed
                && requested_block_number.0 < current_block_number.0
        })
}
```

This mirrors the correct direction used in `validate_proof_block_number` (`proof_block_number > max_allowed` rejects too-recent blocks) and aligns with the Starknet spec for stored block hash availability.

### Proof of Concept

```rust
use blockifier::execution::syscalls::syscall_base::block_number_in_range;
use starknet_api::block::BlockNumber;
use blockifier::abi::constants::STORED_BLOCK_HASH_BUFFER; // e.g., 10

let current = BlockNumber(100);

// Valid recent block — should be in range, but returns false.
let valid = BlockNumber(95); // 100 - 10 + 5 = within [90, 99]
assert!(!block_number_in_range(valid, current)); // BUG: returns false for valid block

// Too-old block — should NOT be in range, but returns true.
let too_old = BlockNumber(89); // older than oldest_allowed=90
assert!(block_number_in_range(too_old, current)); // BUG: returns true for invalid block

// A contract calling get_block_hash(95) would receive an error or Felt::ZERO
// instead of the real block hash, corrupting any logic that depends on it.
```

### Citations

**File:** crates/blockifier/src/execution/syscalls/syscall_base.rs (L519-529)
```rust
/// Returns whether the given block number is within the range of stored block hashes
/// relative to the current block number.
pub fn block_number_in_range(
    requested_block_number: BlockNumber,
    current_block_number: BlockNumber,
) -> bool {
    current_block_number
        .0
        .checked_sub(constants::STORED_BLOCK_HASH_BUFFER)
        .is_some_and(|oldest_allowed| requested_block_number.0 <= oldest_allowed)
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L238-260)
```rust
    fn validate_proof_block_number(
        proof_block_number: u64,
        current_block_number: BlockNumber,
    ) -> TransactionPreValidationResult<()> {
        // Proof block must be old enough to have a stored block hash.
        // Stored block hashes are guaranteed only up to: current - STORED_BLOCK_HASH_BUFFER.
        let max_allowed =
            current_block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER).ok_or_else(|| {
                TransactionPreValidationError::InvalidProofFacts(format!(
                    "The current block number {current_block_number} is below the required \
                     block-hash retention buffer: {STORED_BLOCK_HASH_BUFFER}."
                ))
            })?;

        if proof_block_number > max_allowed {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "The proof block number {proof_block_number} is too recent. The maximum allowed \
                 block number is {max_allowed}."
            )));
        }

        Ok(())
    }
```
