### Title
Missing panic isolation for native/builtin program execution in the production instruction-dispatch path - (File: program-runtime/src/invoke_context.rs)

### Summary
Agave's production instruction execution path (`InvokeContext::process_executable_chain`) invokes native/builtin program entrypoints (System, Vote, Stake-adjacent, BPF loaders, precompiles, Compute Budget, ZK proof programs, etc.) directly through `vm.invoke_function(function)` with no `std::panic::catch_unwind` boundary. This is structurally the same bug class as the referenced rs-soroban-env fix (#548): "Catch panics from native contracts in try_call". In agave, only the test-only `solana-program-test` crate wraps builtin invocation in `catch_unwind` — the real validator dispatch path does not.

### Finding Description
The core instruction dispatch routine in the runtime is `process_executable_chain`: [1](#0-0) 

This function resolves the builtin's registered entrypoint and calls `vm.invoke_function(function)` unconditionally, with no `catch_unwind` around it, before inspecting `vm.program_result`. This function is reached from `process_instruction`, which is called from `InvokeContext::process_message`, which is called from the SVM's production transaction execution path: [2](#0-1) 

By contrast, the test-only harness in `solana-program-test` explicitly wraps the equivalent builtin call in `catch_unwind`, and even has a dedicated regression test (`program-test/tests/panic.rs`) proving that a panicking builtin function is caught and converted into `InstructionError::ProgramFailedToComplete`: [3](#0-2) [4](#0-3) 

The existence of this test-only protection, absent from the production path, indicates the project is aware panics from builtin/native code are possible and disruptive — but the mitigation was only ever applied in the mock/test harness, not in `program-runtime/src/invoke_context.rs`'s real dispatch routine used by the validator, banking stage, and replay stage.

Native/builtin programs are ordinary Rust code containing many `unwrap()`/`expect()`/indexing operations that can panic (e.g. `programs/system/src/system_processor.rs` and `system_instruction.rs` alone contain 73 and 101 matches respectively for `unwrap()/expect()/panic!` patterns). If any reachable code path in a builtin program panics while executing a transaction submitted by an unprivileged sender, the panic unwinds straight through `process_executable_chain` → `process_instruction` → `process_message` → `execute_loaded_transaction` → `load_and_execute_sanitized_transactions`, with no boundary to convert it into a graceful `InstructionError`.

### Impact Explanation
An unhandled panic propagating out of transaction execution on the banking-stage or replay-stage thread can, depending on build/panic configuration and how the caller (bank/replay) handles thread panics, abort the validator process or poison the executing thread/locks, halting further block production or replay for that node. Because the trigger is entirely inside code invoked by processing a single submitted transaction (no special privileges required), a bug that causes any builtin to panic on attacker-chosen input becomes a transaction-triggered denial-of-service / potential cluster-liveness issue if enough validators run the same code path and receive the same crafted transaction (network-wide halt if triggered broadly, e.g. via a widely propagated transaction).

### Likelihood Explanation
The likelihood depends on whether a concrete panic-triggering input exists in any builtin program reachable via `process_executable_chain` (System, Vote, BPF loaders, precompiles, Compute Budget, ZK proof programs). I could not confirm a specific currently-exploitable `unwrap()`/index panic in this investigation window, so this should be treated as an architectural gap (absence of defense-in-depth) rather than a proven, immediately triggerable panic. The comparison to the rs-soroban-env fix is at the level of "the production dispatch path lacks the panic-catching safety net that the codebase itself already considers necessary" (as evidenced by the test-harness fix and regression test).

### Recommendation
Wrap the builtin/native function invocation in `process_executable_chain` (`program-runtime/src/invoke_context.rs`, around `vm.invoke_function(function)`) in `std::panic::catch_unwind(AssertUnwindSafe(...))`, mirroring what `solana-program-test::invoke_builtin_function` already does, and convert any caught panic into `InstructionError::ProgramFailedToComplete` (or a dedicated error) instead of allowing it to unwind into the SVM/bank execution loop. Audit builtin programs (`programs/system`, `programs/vote`, `programs/bpf_loader`, `programs/compute-budget`, `programs/zk-token-proof`, `programs/zk-elgamal-proof`) for panics reachable from attacker-controlled instruction data/account state.

### Proof of Concept
Not independently reproduced with a concrete panic-triggering instruction in this investigation; the structural gap is demonstrated by comparing:
- Production path (no catch_unwind): [5](#0-4) 
- Test-only path (has catch_unwind + regression test proving panics occur and must be caught): [6](#0-5) [7](#0-6)

### Citations

**File:** program-runtime/src/invoke_context.rs (L690-702)
```rust
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
```

**File:** svm/src/transaction_processor.rs (L1112-1116)
```rust
        let mut process_message_time = Measure::start("process_message_time");
        let process_result = invoke_context
            .process_message(tx, execute_timings, &mut executed_units)
            .map_err(|(index, err)| TransactionError::InstructionError(index, err));
        process_message_time.stop();
```

**File:** program-test/src/lib.rs (L154-172)
```rust
    // Execute the program
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        builtin_function(program_id, &account_infos, input)
    })) {
        Ok(program_result) => {
            program_result.map_err(|program_error| {
                let err = InstructionError::from(u64::from(program_error));
                stable_log::program_failure(&log_collector, program_id, &err);
                let err: Box<dyn std::error::Error> = Box::new(err);
                err
            })?;
        }
        Err(_panic_error) => {
            let err = InstructionError::ProgramFailedToComplete;
            stable_log::program_failure(&log_collector, program_id, &err);
            let err: Box<dyn std::error::Error> = Box::new(err);
            Err(err)?;
        }
    };
```

**File:** program-test/tests/panic.rs (L1-40)
```rust
use {
    solana_account_info::AccountInfo,
    solana_instruction::{Instruction, error::InstructionError},
    solana_program_error::ProgramResult,
    solana_program_test::{ProgramTest, processor},
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    solana_transaction::Transaction,
    solana_transaction_error::TransactionError,
};

fn panic(_program_id: &Pubkey, _accounts: &[AccountInfo], _input: &[u8]) -> ProgramResult {
    panic!("I panicked");
}

#[tokio::test]
async fn panic_test() {
    let program_id = Pubkey::new_unique();

    let program_test = ProgramTest::new("panic", program_id, processor!(panic));

    let context = program_test.start_with_context().await;

    let instruction = Instruction::new_with_bytes(program_id, &[], vec![]);

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    assert_eq!(
        context
            .banks_client
            .process_transaction(transaction)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, InstructionError::ProgramFailedToComplete)
    );
```
