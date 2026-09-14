### Title
Precompile signature-verification work (secp256k1/ed25519/secp256r1) is executed with real CPU cost but is never charged against the transaction's compute-unit meter - ([File: program-runtime/src/invoke_context.rs])

### Summary
`InvokeContext::process_message` routes precompile program instructions (`secp256k1_program`, `ed25519_program`, `secp256r1_program`) through a code path (`process_precompile`) that never touches `compute_units_consumed`, unlike ordinary/BPF instructions which go through `process_instruction`/`process_executable_chain` and are forced to consume compute units. The precompile `verify()` routines internally loop over an attacker-controlled signature count and perform genuinely expensive cryptographic work (EC point recovery, ed25519 strict verification, ECDSA P-256 verification) per iteration, none of which is deducted from the transaction's `compute_unit_limit`.

### Finding Description
In `InvokeContext::process_message`, precompile instructions are dispatched separately from normal instructions: [1](#0-0) 

`process_precompile` simply forwards to the callback's verifier and never updates `compute_units_consumed`: [2](#0-1) 

By contrast, the normal execution path (`process_executable_chain`) measures `pre_remaining_units`/`post_remaining_units` and even hard-fails a builtin if it doesn't consume any compute units: [3](#0-2) 

This is confirmed by an explicit test comment stating a precompile instruction consumes `0` CU from the compute meter: [4](#0-3) 

The precompile `verify` functions themselves loop over a count that is read directly from attacker-controlled instruction data (`data[0]`), up to `255` for secp256k1/ed25519 and `8` for secp256r1, and each iteration performs a full cryptographic verification/recovery operation: [5](#0-4) [6](#0-5) [7](#0-6) 

Because signature/pubkey/message data can be sourced via 11-14 byte offset structures that point into *any* other instruction in the same transaction (including a small shared instruction), an attacker does not need to inflate transaction size proportionally to the number of expensive verifications requested — only ~11-14 bytes per additional signature entry are needed, letting a single ~1232-byte transaction request on the order of 100+ real elliptic-curve recovery/verification operations.

While `cost-model/src/cost_model.rs::get_signature_cost` does scale a cost estimate with the declared per-instruction signature count (via `PrecompileSignatureDetails` in `runtime-transaction/src/signature_details.rs`), this is used for leader-side block-cost/scheduling accounting, not for gating or deducting from the transaction's actual `compute_unit_limit`/compute meter during execution. The `InstructionError::BuiltinProgramsMustConsumeComputeUnits` guard that protects ordinary builtins from silently doing free work is explicitly bypassed for precompiles. [8](#0-7) [9](#0-8) 

### Impact Explanation
A single unprivileged, correctly-sanitized transaction can force every validator that ingests or replays it (leader during packing and every replaying validator) to perform disproportionately expensive cryptographic verification work compared to the compute units the sender is required to purchase for that work — the precompile loop consumes zero units from the transaction's own compute-unit budget. This decouples the real CPU cost of processing the transaction from the resource-accounting mechanism (`compute_unit_limit`/CU meter) that is supposed to bound and price per-transaction execution cost, which is squarely in the "fee and compute-budget accounting" and "precompiles" categories called out as in-scope. This is a resource-exhaustion/amplification primitive rather than a fund-theft bug; the practical severity is bounded by transaction size limits (~100+ signature verifications per transaction, not unbounded), so it should be scoped as a compute-budget accounting defect rather than a full cluster halt.

### Likelihood Explanation
High reachability: any account can submit a transaction containing `secp256k1_program`/`ed25519_program`/`secp256r1_program` instructions with maximal declared signature counts and offsets that reuse existing instruction bytes; no privileged accounts, CPI, or special program deployment is required. The bypass of CU accounting for precompiles is a structural property of `process_message`/`process_precompile`, not a rare edge case.

### Recommendation
Meter the precompile verification work against the transaction's compute budget, e.g., by charging the same per-signature costs used in `cost-model/src/cost_model.rs` (`SECP256K1_VERIFY_COST`, `ED25519_VERIFY_STRICT_COST`, `SECP256R1_VERIFY_COST`) from the invoke context's compute meter inside `process_precompile` (or before dispatch in `process_message`), and fail the transaction with `ComputationalBudgetExceeded` if the declared/actual signature count exceeds the remaining budget, consistent with how `process_executable_chain` enforces `BuiltinProgramsMustConsumeComputeUnits` for ordinary builtins.

### Proof of Concept
Not independently executed (index-only analysis); reasoning based on static code paths:
1. Construct a legacy or v0 transaction (≤ ~1232 bytes) containing a `secp256k1_program` instruction with `data[0]` (count) set near the maximum supported by remaining space (~100+ entries), each `SecpSignatureOffsets` entry pointing its `signature/eth_address/message` offsets into one small shared instruction present elsewhere in the same transaction (per `precompiles/src/secp256k1.rs` `get_data_slice`, referenced instructions can be reused).
2. Set `ComputeBudgetInstruction::set_compute_unit_limit` to a minimal value (e.g., a few hundred CU) — the precompile loop consumes 0 CU per `process_precompile` in `program-runtime/src/invoke_context.rs:616-631`, so the low CU limit does not block execution.
3. Submit the transaction; each validator that verifies/executes it (leader and replayers) performs ~100 real `libsecp256k1::recover` operations in `precompiles/src/secp256k1.rs:44-101` while the sender pays fees/compute budget as if the transaction did negligible work.
4. Repeat with many such transactions in a block to amplify aggregate CPU cost imposed on validators relative to the CU/fee actually charged.

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

**File:** program-runtime/src/invoke_context.rs (L672-729)
```rust
        let program_id = *instruction_context.get_program_key()?;
        self.transaction_context
            .set_return_data(program_id, Vec::new())?;
        let logger = self.get_log_collector();
        stable_log::program_invoke(&logger, &program_id, self.get_stack_height());
        let pre_remaining_units = self.get_remaining();
        // For now, only built-ins are invoked from here, so the VM and its Config are irrelevant.
        self.memory_contexts
            .set_memory_context_abi_v1(MemoryContext::new(
                BpfAllocator::new(0),
                Vec::new(),
                // SAFETY:
                // This path invokes a builtin program, so this mapping is never used.
                unsafe {
                    MemoryMapping::new(Vec::new(), &Config::default(), SBPFVersion::Reserved)
                        .unwrap()
                },
            ))?;
        let mut vm = EbpfVm::new(
            Arc::clone(
                &**self
                    .environment_config
                    .program_runtime_environments
                    .get_env_for_execution(),
            ),
            SBPFVersion::V0,
            // Removes lifetime tracking
            unsafe { std::mem::transmute::<&mut InvokeContext, &mut InvokeContext>(self) },
            0,
        );
        vm.invoke_function(function);
        let result = match vm.program_result {
            ProgramResult::Ok(_) => {
                stable_log::program_success(&logger, &program_id);
                Ok(())
            }
            ProgramResult::Err(ref err) => {
                if let EbpfError::SyscallError(syscall_error) = err {
                    if let Some(instruction_err) = syscall_error.downcast_ref::<InstructionError>()
                    {
                        stable_log::program_failure(&logger, &program_id, instruction_err);
                        Err(instruction_err.clone())
                    } else {
                        stable_log::program_failure(&logger, &program_id, syscall_error);
                        Err(InstructionError::ProgramFailedToComplete)
                    }
                } else {
                    stable_log::program_failure(&logger, &program_id, err);
                    Err(InstructionError::ProgramFailedToComplete)
                }
            }
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

**File:** precompiles/src/secp256k1.rs (L23-44)
```rust
pub fn verify(
    data: &[u8],
    instruction_datas: &[&[u8]],
    _feature_set: &FeatureSet,
) -> Result<(), PrecompileError> {
    if data.is_empty() {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
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

**File:** precompiles/src/secp256r1.rs (L18-41)
```rust
pub fn verify(
    data: &[u8],
    instruction_datas: &[&[u8]],
    _feature_set: &FeatureSet,
) -> Result<(), PrecompileError> {
    if data.len() < SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let num_signatures = data[0] as usize;
    if num_signatures == 0 {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    if num_signatures > 8 {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }

    let expected_data_size = num_signatures
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(SIGNATURE_OFFSETS_START);

    // We do not check or use the byte at data[1]
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
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
