### Title
Precompile signature verification cost is charged at a flat per-signature rate independent of `message_data_size`, letting a single transaction force disproportionate CPU work relative to its accounted compute/fee cost - (File: cost-model/src/block_cost_limits.rs, precompiles/src/secp256k1.rs, precompiles/src/ed25519.rs, precompiles/src/secp256r1.rs)

### Summary
The `secp256k1`, `ed25519`, and `secp256r1` precompiles each loop over an attacker-controlled `num_signatures`/`count` byte (up to 255) and, per iteration, hash/verify a `message_data_size` (up to 65535 bytes, `u16`) slice pulled from arbitrary instruction data offsets. The cost model, however, charges a fixed per-signature constant (`SECP256K1_VERIFY_COST`, `ED25519_VERIFY_STRICT_COST`, `SECP256R1_VERIFY_COST`) that does not scale with `message_data_size`, and the actual verification work executed via `InvokeContext::process_precompile` never draws from the compute meter at all.

### Finding Description
Each precompile `verify()` function parses a signature count directly from instruction data and loops that many times, each iteration reading a `message_data_size` field (a `u16`, up to 65535) and hashing/verifying that many bytes: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

The `secp256r1` precompile caps `num_signatures` at 8, but `ed25519` and `secp256k1` have no analogous cap beyond the implicit `u8` maximum of 255: [5](#0-4) 

At the on-chain execution layer, the actual verification work is dispatched via `process_precompile`, which never calls `compute_meter.consume_checked` for the real work performed — unlike ordinary builtin/BPF instruction execution, where compute unit consumption is measured and enforced: [6](#0-5) 
This is confirmed by an existing test comment noting that for a precompiled instruction, "VM Execution: consume 0 from CU-meter": [7](#0-6) 

For fee and block-cost-limiting purposes, `CostModel::get_signature_cost` charges a **flat** per-signature constant multiplied only by signature *count*, with no dependency on message length: [8](#0-7) 
The constants themselves are fixed values unrelated to the actual bytes hashed/verified: [9](#0-8) 

This is the same bug class as the JWE `p2c` PBES2 issue: an attacker-controlled parameter (here, `message_data_size` combined with signature `count`) directly drives the amount of expensive cryptographic work (keccak256 hashing + secp256k1 EC point recovery, Ed25519 `verify_strict`, or OpenSSL ECDSA verification over the P-256 curve) performed by the validator, while the cost/fee model charges only a fixed rate that assumes a constant per-signature cost, not accounting for the actual message size processed. Additionally, the underlying VM/compute-budget accounting path for precompiles performs no metering at all of this work, so there is no runtime backstop that would abort processing once real computational cost exceeds what was paid for.

### Impact Explanation
A transaction can pack a precompile instruction with the maximum signature count (255 for `secp256k1`/`ed25519`) where every signature entry's offsets point at the same large `message_data_size` slice (bounded only by the ~1232-byte transaction packet size, but reusable/rehashed up to 255 times). This multiplies the real cryptographic work (elliptic-curve point recovery/signature verification, which are the most CPU-expensive operations in the validator's transaction pipeline) far beyond what the flat per-signature cost model constant accounts for, and this real work is entirely un-metered against the transaction's compute budget. This can be used to make an unprivileged sender's transactions consume CPU disproportionate to their priced cost/fee — a resource-exhaustion condition analogous to the JWE `p2c` issue, potentially degrading leader block production or sigverify throughput if repeated across many transactions/instructions.

### Likelihood Explanation
High from a reachability standpoint: any unprivileged transaction sender can submit `secp256k1_program`/`ed25519_program` instructions with a crafted `count` and offsets, requiring no special privileges, precompiled program invocation is a standard, permissionless transaction feature.

### Recommendation
Scale the cost-model constants for precompile signature verification (`SECP256K1_VERIFY_COST`, `ED25519_VERIFY_STRICT_COST`) by `message_data_size` (as `secp256r1` already partially mitigates via its 8-signature cap, though it too lacks message-length scaling), and/or meter the actual bytes hashed/verified inside `process_precompile`/`InvokeContext` against the compute budget rather than leaving it entirely un-metered.

### Proof of Concept
Not independently verified end-to-end in this pass (no execution/benchmarking tool available); the vector is: build a transaction with a single `secp256k1_program` (or `ed25519_program`) instruction whose `count`/`num_signatures` byte is 255, with every `SecpSignatureOffsets`/`Ed25519SignatureOffsets` entry's `message_instruction_index`/`message_data_offset`/`message_data_size` pointing at the same large slice of another instruction's data (as large as the ~1232-byte packet allows), causing 255 EC-recovery/keccak or Ed25519 `verify_strict` operations to run in `verify()` while `CostModel::get_signature_cost` charges only `255 * SECP256K1_VERIFY_COST` (a fixed per-signature amount) and `process_precompile` consumes 0 compute units for the work performed.

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

**File:** cost-model/src/cost_model.rs (L128-150)
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
