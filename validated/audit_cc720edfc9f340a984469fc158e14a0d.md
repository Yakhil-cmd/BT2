### Title
Precompile signature-count/message-length cost accounting is not proportional to actual verification work, enabling amplified CPU consumption per submitted transaction - (File: `precompiles/src/secp256k1.rs`, `precompiles/src/ed25519.rs`, `cost-model/src/block_cost_limits.rs`)

### Summary
The Discourse advisory describes a DoS where a request can trigger fetching an unbounded amount of work (all replies to a post) for a cost disproportionate to what the server actually charges/limits for the request. The closest reachable analog in Agave is the `secp256k1`/`ed25519` precompile verification path: the cost model charges a **flat, fixed cost per declared signature** (`SECP256K1_VERIFY_COST`, `ED25519_VERIFY_STRICT_COST`) that does not scale with the size of the message each signature is hashed over, while the actual precompile `verify()` implementations allow up to 255 signature entries per instruction, each independently pointing (via `message_instruction_index`/`message_data_offset`/`message_data_size`, a `u16`) at a message of up to ~64 KB, and multiple signature entries are free to reuse the very same message bytes.

### Finding Description
`precompiles/src/secp256k1.rs::verify` and `precompiles/src/ed25519.rs::verify` iterate `count`/`num_signatures` (up to `u8::MAX` = 255) signature-offset entries per precompile instruction: [1](#0-0) [2](#0-1) 

For each entry, the message slice is looked up from `instruction_datas` using attacker-controlled `message_instruction_index` / `message_data_offset` / `message_data_size` (a `u16`, so up to 65535 bytes): [3](#0-2) [4](#0-3) 

Nothing prevents many signature entries from pointing at the *same* message bytes stored once in another instruction's data — the offsets are just indices, not unique-message constraints. Each entry then performs a full keccak-256 hash (secp256k1) or SHA-512/verify_strict (ed25519) over that message, plus an EC recovery or signature verification: [5](#0-4) [6](#0-5) 

The runtime's cost model, however, charges signature-verification cost as a flat per-signature constant, independent of the message size being hashed on each iteration: [7](#0-6) 
and separately charges instruction *data bytes* once at a flat rate (`INSTRUCTION_DATA_BYTES_COST`), not multiplied by the number of times that data is re-hashed by repeated signature offsets: [8](#0-7) 
The signature counts driving this cost come straight from the first data byte of each precompile instruction, with no cap analogous to `secp256r1`'s `num_signatures > 8` check: [9](#0-8) 
Notably, `secp256r1.rs` *does* clamp `num_signatures` to 8 explicitly: [10](#0-9) 
but `secp256k1.rs` and `ed25519.rs` have no equivalent maximum, allowing up to 255 signature verifications per instruction, each potentially hashing a large shared message.

Precompile execution is also treated by the cost model as a fixed "builtin" allocation, not tied at all to the number of signatures/verifications performed inside it, as shown by the test asserting a flat `MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT` cost adjustment for a whole precompiled instruction regardless of its internal signature count: [11](#0-10) 
This is consistent with `SVM Execution: consume 0 from CU-meter` noted in that same test, i.e. precompile verification work is not metered by the SBF compute-unit meter at all; only the separate, non-work-proportional `signature_cost` in the cost model is meant to bound it, and that signature cost — as shown above — does not scale with the size of the (re-used) message.

### Impact Explanation
A single unprivileged transaction can be constructed to force the leader/validator that processes it (during `verify_if_precompile` / `Bank::verify_transaction`) to perform hundreds of expensive cryptographic hash + EC operations over large, repeatedly-referenced message payloads, while the transaction's accounted "signature cost" for block-cost-limit and per-transaction compute-unit purposes reflects only a flat per-signature charge that under-represents the true CPU work relative to message size. This can degrade validator/leader throughput and availability for a cost far below what actual verification work would imply — the same "unbounded fetch/compute behind a cheap request" pattern as the Discourse advisory, but expressed as unbounded hashing work behind a fixed per-signature accounting unit.

### Likelihood Explanation
Reachable by any unprivileged transaction sender: constructing `secp256k1`/`ed25519` instructions with the maximum `count`/`num_signatures` (255) and offsets that all reference one large (~64 KB) message blob included once in the transaction requires no special privileges, no cluster state, and no cooperation from validators or leaders — only standard instruction construction. The lack of a signature-count cap in `secp256k1.rs`/`ed25519.rs` (unlike the explicit cap present in `secp256r1.rs`) makes this straightforward to trigger.

### Recommendation
- Add an explicit maximum on `num_signatures`/`count` in `secp256k1::verify` and `ed25519::verify` analogous to the `secp256r1` check (`num_signatures > 8`).
- Make the signature-verification cost model account for message size (e.g., scale `SECP256K1_VERIFY_COST`/`ED25519_VERIFY_STRICT_COST` by the referenced message length, or charge instruction-data cost per signature-offset reference rather than once per unique byte range) so that repeated hashing of the same large message by many signature entries is reflected in the accounted cost.
- Consider metering precompile verification work directly against the SBF compute-unit budget rather than relying solely on a fixed builtin allocation.

### Proof of Concept
Conceptually (not run, since this is a static-review answer):
1. Build a `secp256k1` instruction whose data contains `count = 255` signature-offset entries, all with `message_instruction_index` pointing to instruction `X`, and identical `message_offset = 0`, `message_data_size = 65000` (or the max size that fits within the transaction/packet size limit).
2. Include instruction `X` in the same transaction, containing a single ~64 KB (or largest permissible) buffer as its data (subject to overall transaction size limits, e.g. `solana_message::v1::MAX_TRANSACTION_SIZE` for tx v1 or `PACKET_DATA_SIZE` for legacy/v0).
3. Submit the transaction. `verify_if_precompile`/`Bank::verify_transaction` will invoke `secp256k1::verify`, causing 255 keccak-256 hashes over the ~64 KB buffer plus 255 `libsecp256k1::recover` calls, while the transaction's signature cost in the cost model only reflects `255 * SECP256K1_VERIFY_COST` (a fixed per-signature unit unrelated to the 64 KB message size), understating the real work multiple times over relative to a transaction with equally many *unique* smaller messages that the cost constants were presumably calibrated against.

*Note: I was not able to fully verify the exact per-transaction maximum instruction/message size ceilings (`solana_message::v1::MAX_TRANSACTION_SIZE`, `MAX_INSTRUCTION_TRACE_LENGTH`) or the precise numeric impact multiplier within the available search results, so the magnitude of real-world CPU amplification versus accounted cost should be empirically measured (e.g., via the existing `precompiles/benches/*` benchmarks) before treating this as confirmed exploitable at scale.*

### Citations

**File:** precompiles/src/secp256k1.rs (L31-44)
```rust
    let count = data[0] as usize;
    if count == 0 && data.len() > 1 {
        // count is zero but the instruction data indicates that is probably not
        // correct, fail the instruction to catch probable invalid secp256k1
        // instruction construction.
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let expected_data_size = count
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(1);
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    for i in 0..count {
```

**File:** precompiles/src/secp256k1.rs (L81-87)
```rust
        // Parse out message
        let message_slice = get_data_slice(
            instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size as usize,
        )?;
```

**File:** precompiles/src/secp256k1.rs (L88-100)
```rust

        let message_hash: [u8; 32] = solana_keccak_hasher::hash(message_slice).to_bytes();
        let pubkey = libsecp256k1::recover(
            &libsecp256k1::Message::parse_slice(&message_hash).unwrap(),
            &signature,
            &recovery_id,
        )
        .map_err(|_| PrecompileError::InvalidSignature)?;
        let eth_address = eth_address_from_pubkey(&pubkey.serialize()[1..].try_into().unwrap());

        if eth_address_slice != eth_address {
            return Err(PrecompileError::InvalidSignature);
        }
```

**File:** precompiles/src/ed25519.rs (L19-30)
```rust
    let num_signatures = data[0] as usize;
    if num_signatures == 0 && data.len() > SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let expected_data_size = num_signatures
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(SIGNATURE_OFFSETS_START);
    // We do not check or use the byte at data[1]
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    for i in 0..num_signatures {
```

**File:** precompiles/src/ed25519.rs (L66-77)
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
    }
```

**File:** cost-model/src/block_cost_limits.rs (L9-20)
```rust
/// Number of compute units for one signature verification.
pub const SIGNATURE_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 24;
/// Number of compute units for one secp256k1 signature verification.
pub const SECP256K1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 223;
/// Number of compute units for one ed25519 strict signature verification.
pub const ED25519_VERIFY_STRICT_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 80;
/// Number of compute units for one secp256r1 signature verification.
pub const SECP256R1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 160;
/// Number of compute units for one write lock
pub const WRITE_LOCK_UNITS: u64 = COMPUTE_UNIT_TO_US_RATIO * 10;
/// Number of data bytes per compute units
pub const INSTRUCTION_DATA_BYTES_COST: u64 = 140 /*bytes per us*/ / COMPUTE_UNIT_TO_US_RATIO;
```

**File:** cost-model/src/cost_model.rs (L103-127)
```rust
    fn calculate_transaction_cost<'a, Tx: TransactionMeta>(
        transaction: &'a Tx,
        instructions: impl Iterator<Item = (&'a Pubkey, SVMInstruction<'a>)>,
        num_write_locks: u64,
        programs_execution_cost: u64,
        loaded_accounts_data_size_cost: u64,
        data_bytes_cost: u16,
        feature_set: &FeatureSet,
    ) -> TransactionCost<'a, Tx> {
        let signature_cost = Self::get_signature_cost(transaction);
        let write_lock_cost = Self::get_write_lock_cost(num_write_locks);

        let allocated_accounts_data_size =
            Self::calculate_allocated_accounts_data_size(instructions, feature_set);

        TransactionCost {
            transaction,
            signature_cost,
            write_lock_cost,
            data_bytes_cost,
            programs_execution_cost,
            loaded_accounts_data_size_cost,
            allocated_accounts_data_size,
        }
    }
```

**File:** runtime-transaction/src/signature_details.rs (L60-74)
```rust
/// Get transaction signature details.
pub fn get_precompile_signature_details<'a>(
    instructions: impl Iterator<Item = (&'a Pubkey, SVMInstruction<'a>)>,
) -> PrecompileSignatureDetails {
    let mut builder = PrecompileSignatureDetailsBuilder::default();
    for (program_id, instruction) in instructions {
        builder.process_instruction(program_id, &instruction);
    }
    builder.build()
}

#[inline]
fn get_num_signatures_in_instruction(instruction: &SVMInstruction) -> u64 {
    u64::from(instruction.data.first().copied().unwrap_or(0))
}
```

**File:** precompiles/src/secp256r1.rs (L26-32)
```rust
    let num_signatures = data[0] as usize;
    if num_signatures == 0 {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    if num_signatures > 8 {
        return Err(PrecompileError::InvalidInstructionDataSize);
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
