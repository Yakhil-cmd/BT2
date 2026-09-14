### Title
Precompile signature verification consumes zero compute units regardless of success or failure - ([File: program-runtime/src/invoke_context.rs])

### Summary
The reported EVM bug is that `Restore()` performs expensive signature verification work (scaling with attacker-supplied buffer size) but only charges the cheap intrinsic gas when the signature check fails, since the real cost accounting never gets reached. The equivalent path in this codebase is Agave's precompile-instruction handling (`secp256k1`, `ed25519`, `secp256r1` programs), which performs real cryptographic work (ECDSA recovery + keccak hashing, `ed25519_dalek::verify_strict`, or OpenSSL EC-point/ECDSA operations) proportional to attacker-controlled message size and signature count, but the compute-unit metering path for precompiles bypasses the compute meter entirely — unlike ordinary builtin/BPF instructions, which are required to consume compute units.

### Finding Description
In `InvokeContext::process_message`, precompile instructions are dispatched to a special path instead of the normal instruction-execution path: [1](#0-0) 

`process_precompile` performs the actual (potentially expensive) verification work via the `epoch_stake_callback.process_precompile(...)` call — the same `agave_precompiles::{secp256k1,ed25519,secp256r1}::verify` functions shown in `precompiles/src/secp256k1.rs`, `precompiles/src/ed25519.rs`, and `precompiles/src/secp256r1.rs` — but it never touches `invoke_context.compute_meter`: [2](#0-1) 

Contrast this with the normal builtin-execution path, `process_executable_chain`, which explicitly measures compute units consumed and enforces that *any* successful builtin program must consume a non-zero amount, via the `BuiltinProgramsMustConsumeComputeUnits` check: [3](#0-2) 

Because `process_precompile` returns directly without ever calling `compute_meter.consume_checked(...)`, this invariant is skipped entirely for precompiles. This is confirmed by an existing test/comment that documents the current, by-design behavior: [4](#0-3) 

Separately, the cost-model estimate used for block-packing/fee purposes (`SECP256K1_VERIFY_COST`, `ED25519_VERIFY_STRICT_COST`, `SECP256R1_VERIFY_COST`) is a fixed constant multiplied only by the *count* of signatures declared in the instruction's leading byte — it does not scale with the size of the message being verified: [5](#0-4) [6](#0-5) 

The actual verification cost, however, is a function of message size (`offsets.message_data_size`, a `u16`, up to 65,535 bytes) as seen in the `verify` implementations, e.g. `ed25519::verify` hashing/verifying the full `message` slice and `secp256k1::verify` hashing the message with keccak before ECDSA recovery: [7](#0-6) [8](#0-7) 

This means: (1) the compute meter (the per-transaction resource ledger checked against `compute_unit_limit`) is never decremented for the real CPU work of signature verification, whether it succeeds or fails, and (2) even the coarse cost-model estimate used elsewhere for scheduling is insensitive to the message size, only to signature count.

### Impact Explanation
Unlike the EVM report — where an attacker can submit arbitrarily huge buffers for near-zero cost because Solidity/EVM has no hard transaction-size cap — Agave transactions are bounded by packet/transaction size limits enforced during sanitization (`verify_transaction_with_serialized_message` in `runtime/src/bank.rs`), which caps the referenced instruction data (and hence the maximum message size any single precompile signature can verify). I could not fully confirm the exact numeric ceiling for `v1` transactions within the available index (`MAX_TRANSACTION_SIZE`/`PACKET_DATA_SIZE` constants were not resolved by search), so I cannot definitively quantify how large a single verifiable message can be for the newer v1 transaction format.

Given that bound, this is a **weaker analog** than the EVM finding: it does not by itself enable unsigned fund movement, consensus divergence, or a cluster-halting DoS, because block-level compute limits (`MAX_BLOCK_UNITS`) are still enforced using the signature-count-based cost estimate, which caps the number of precompile signature verifications that fit in a block, and the metering gap is scoped to the resource-accounting mismatch (real CPU cost not reflected in the compute meter or the size-insensitive fixed cost estimate) rather than a bypass of resource limits proportional to unbounded attacker input.

### Likelihood Explanation
Any unprivileged transaction sender can trivially construct a transaction containing failing (or succeeding) `secp256k1`/`ed25519`/`secp256r1` precompile instructions with maximum-size offset-referenced messages and multiple signatures (up to 255 for secp256k1/ed25519, 8 for secp256r1) — no special privileges are required, and this is reachable purely through normal transaction submission.

### Recommendation
Charge compute units for precompile verification proportional to the actual work performed (message size and signature count), and enforce the same "must consume compute units" invariant used for ordinary builtins in `process_precompile`, rather than allowing it to bypass `compute_meter.consume_checked(...)` entirely. This closes the resource-accounting gap regardless of verification outcome (success or failure), consistent with the external report's core recommendation of consuming resource cost proportional to work performed even on invalid-signature failure.

### Proof of Concept
Not fully constructible from the indexed code alone; the existing test `test_builtin_ix_precompiled` in `core/tests/scheduler_cost_adjustment.rs` already demonstrates that a precompile instruction consumes `0` from the compute-unit meter during VM execution regardless of the instruction's outcome. A full PoC would submit a transaction with one or more `secp256k1`/`ed25519`/`secp256r1` instructions referencing maximum-size messages (via `message_data_size`/offsets) and observe that `compute_units_consumed` reported by `InvokeContext::process_message` remains `0` for the precompile instruction even though real cryptographic work (hashing + EC operations) was performed — but I could not verify the exact maximum referencable message size bound (transaction size limit constant) within this session, which limits precise quantification of the exploit's real-world severity.

### Citations

**File:** program-runtime/src/invoke_context.rs (L514-525)
```rust
            let mut compute_units_consumed = 0;
            let (result, process_instruction_us) = measure_us!({
                if self.is_precompile(program_id) {
                    self.process_precompile(
                        program_id,
                        instruction.data,
                        message.instructions_iter().map(|ix| ix.data),
                    )
                } else {
                    self.process_instruction(&mut compute_units_consumed, execute_timings)
                }
            });
```

**File:** program-runtime/src/invoke_context.rs (L616-631)
```rust
    /// Processes a precompile instruction
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn process_precompile(
        &mut self,
        program_id: &Pubkey,
        instruction_data: &[u8],
        message_instruction_datas_iter: impl Iterator<Item = &'ix_data [u8]>,
    ) -> Result<(), InstructionError> {
        self.push()?;
        let instruction_datas: Vec<_> = message_instruction_datas_iter.collect();
        self.environment_config
            .epoch_stake_callback
            .process_precompile(program_id, instruction_data, instruction_datas)
            .map_err(InstructionError::from)
            .and(self.pop())
    }
```

**File:** program-runtime/src/invoke_context.rs (L723-729)
```rust
        };
        let post_remaining_units = self.get_remaining();
        *compute_units_consumed = pre_remaining_units.saturating_sub(post_remaining_units);

        if builtin_id == program_id && result.is_ok() && *compute_units_consumed == 0 {
            return Err(InstructionError::BuiltinProgramsMustConsumeComputeUnits);
        }
```

**File:** core/tests/scheduler_cost_adjustment.rs (L381-402)
```rust
#[test]
fn test_builtin_ix_precompiled() {
    let mut test_setup = TestSetup::new();

    // single precompiled instruction
    // Cost model & Compute budget: reserve/allocate default CU for one builtin ix
    // VM Execution: consume 0 from CU-meter
    // Result: adjustment = 3_000
    let expected = TestResult {
        cost_adjustment: MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT as i64,
        execution_status: Ok(()),
    };
    assert_eq!(
        expected,
        test_setup.execute_test_transaction(&[Instruction::new_with_bincode(
            secp256k1_program::id(),
            &[0u8],
            // Add a dummy account to generate a unique transaction
            vec![AccountMeta::new_readonly(Pubkey::new_unique(), false)]
        )],)
    );
}
```

**File:** cost-model/src/block_cost_limits.rs (L9-16)
```rust
/// Number of compute units for one signature verification.
pub const SIGNATURE_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 24;
/// Number of compute units for one secp256k1 signature verification.
pub const SECP256K1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 223;
/// Number of compute units for one ed25519 strict signature verification.
pub const ED25519_VERIFY_STRICT_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 80;
/// Number of compute units for one secp256r1 signature verification.
pub const SECP256R1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 160;
```

**File:** cost-model/src/cost_model.rs (L129-151)
```rust
    /// Returns signature details and the total signature cost
    fn get_signature_cost(transaction: &impl TransactionMeta) -> u64 {
        let signatures_count_detail = transaction.signature_details();

        signatures_count_detail
            .num_transaction_signatures()
            .saturating_mul(SIGNATURE_COST)
            .saturating_add(
                signatures_count_detail
                    .num_secp256k1_instruction_signatures()
                    .saturating_mul(SECP256K1_VERIFY_COST),
            )
            .saturating_add(
                signatures_count_detail
                    .num_ed25519_instruction_signatures()
                    .saturating_mul(ED25519_VERIFY_STRICT_COST),
            )
            .saturating_add(
                signatures_count_detail
                    .num_secp256r1_instruction_signatures()
                    .saturating_mul(SECP256R1_VERIFY_COST),
            )
    }
```

**File:** precompiles/src/ed25519.rs (L66-76)
```rust
        // Parse out message
        let message = get_data_slice(
            data,
            instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size as usize,
        )?;
        publickey
            .verify_strict(message, &signature)
            .map_err(|_| PrecompileError::InvalidSignature)?;
```

**File:** precompiles/src/secp256k1.rs (L81-96)
```rust
        // Parse out message
        let message_slice = get_data_slice(
            instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size as usize,
        )?;

        let message_hash: [u8; 32] = solana_keccak_hasher::hash(message_slice).to_bytes();
        let pubkey = libsecp256k1::recover(
            &libsecp256k1::Message::parse_slice(&message_hash).unwrap(),
            &signature,
            &recovery_id,
        )
        .map_err(|_| PrecompileError::InvalidSignature)?;
        let eth_address = eth_address_from_pubkey(&pubkey.serialize()[1..].try_into().unwrap());
```
