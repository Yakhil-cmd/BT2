No vulnerability found for this question.

**Analysis:** The `is_simulation` flag referenced in `prologue_common`/`skip_auth_key_check` in `transaction_validation.move` [1](#0-0)  is not an attacker-supplied transaction field. It originates from a private Rust-level field `is_simulation: bool` on the `AptosVM` struct itself [2](#0-1) , which defaults to `false` in `AptosVM::new` and is only ever set to `true` inside `AptosSimulationVM::create_vm_and_simulate_signed_transaction`, a dedicated entrypoint that explicitly requires the transaction signature to be invalid (`assert_err!(transaction.verify_signature(), ...)`) before constructing a fresh VM instance with `vm.is_simulation = true` [3](#0-2) . This value is then threaded down through `run_prologue_with_payload` → `run_script_prologue` → the Move prologue function as a `MoveValue::Bool` argument constructed by the Rust VM code, not deserialized from the submitted transaction bytes [4](#0-3) .

There is no code path in the normal (non-simulation) `execute_user_transaction`/`validate_transaction` flow — which handles real, unprivileged transaction admission via mempool/vm-validator — that allows an attacker to inject or flip this flag to `true`. The premise that an "unprivileged attacker" could "forge is_simulation=true ... through a non-simulation execution entrypoint" is not supported: the flag is provenance-bound to the VM instance construction path, not to any parseable/attacker-controlled transaction or authenticator field. Additionally, the specific file cited in the question, `third_party/move/move-vm/runtime/src/interpreter_caches.rs`, does not exist in this repository, and no `interpreter_caches.rs` file was found via search.

Since the attack requires control over a value that is exclusively set by trusted, non-attacker-reachable Rust code paths (the simulation API construction), this does not meet the admission-review bar of "unprivileged input gets a transaction admitted or rebound" — there is no unprivileged trigger for this condition in real (non-simulated) execution.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L625-627)
```text
    inline fun skip_auth_key_check(is_simulation: bool, auth_key: &Option<vector<u8>>): bool {
        is_simulation && (auth_key.is_none() || auth_key.borrow().is_empty())
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L287-308)
```rust
pub struct AptosVM {
    is_simulation: bool,
    env: AptosEnvironment,
    /// If true, user payloads are allowed not to run extra checks and instead trace execution. If
    /// so, Block-STM replays the trace and performs these checks at post-commit time once. Note
    /// that checks might still be performed in-place based on a heuristic such as payload type.
    async_runtime_checks_enabled: bool,
}

impl AptosVM {
    /// Creates a new VM instance based on the runtime environment. The VM can then be used by
    /// block executor to create multiple tasks sharing the same execution configurations extracted
    /// from the environment.
    pub fn new(env: &AptosEnvironment) -> Self {
        Self {
            is_simulation: false,
            env: env.clone(),
            // There is no tracing by default because it can only be done if there is access to
            // Block-STM.
            async_runtime_checks_enabled: false,
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3622-3655)
```rust
    /// Simulates a signed transaction (i.e., executes it without performing
    /// signature verification) on a newly created VM instance.
    /// *Precondition:* the transaction must **not** have a valid signature.
    pub fn create_vm_and_simulate_signed_transaction(
        transaction: &SignedTransaction,
        state_view: &impl StateView,
    ) -> (VMStatus, TransactionOutput) {
        assert_err!(
            transaction.verify_signature(),
            "Simulated transaction should not have a valid signature"
        );

        let env = AptosEnvironment::new(state_view);
        let mut vm = AptosVM::new(&env);
        vm.is_simulation = true;

        let log_context = AdapterLogSchema::new(state_view.id(), 0);
        let original_view = state_view.as_move_resolver();
        let patched_view = Self::patch_randomness_seed(&original_view);
        let resolver = vm.as_move_resolver(&patched_view);
        let code_storage = state_view.as_aptos_code_storage(&env);

        let (vm_status, vm_output) = vm.execute_user_transaction(
            &resolver,
            &code_storage,
            transaction,
            &log_context,
            &AuxiliaryInfo::new_timestamp_not_yet_assigned(0),
        );
        let txn_output = vm_output
            .into_transaction_output()
            .expect("Converting to transaction output should never fail");
        (vm_status, txn_output)
    }
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L146-207)
```rust
    if features.is_account_abstraction_enabled()
        || features.is_derivable_account_abstraction_enabled()
    {
        let secondary_auth_keys: Vec<MoveValue> = txn_data
            .secondary_authentication_proofs
            .iter()
            .map(|auth_key| auth_key.optional_auth_key().as_move_value())
            .collect();
        let replay_protector_move_value = if features.is_transaction_payload_v2_enabled() {
            txn_replay_protector
                .to_move_value()
                .simple_serialize()
                .unwrap()
        } else {
            match txn_replay_protector {
                ReplayProtector::SequenceNumber(seq_num) => {
                    MoveValue::U64(seq_num).simple_serialize().unwrap()
                },
                ReplayProtector::Nonce(_) => {
                    unreachable!("Orderless transactions are discarded already")
                },
            }
        };

        let (prologue_function_name, serialized_args) = if let (true, Some(fee_payer_auth_key)) = (
            txn_data.fee_payer().is_some(),
            txn_data
                .fee_payer_authentication_proof
                .as_ref()
                .map(|proof| proof.optional_auth_key()),
        ) {
            let serialized_args = vec![
                serialized_signers.sender(),
                serialized_signers
                    .fee_payer()
                    .ok_or_else(|| VMStatus::error(StatusCode::UNREACHABLE, None))?,
                txn_authentication_key
                    .as_move_value()
                    .simple_serialize()
                    .unwrap(),
                fee_payer_auth_key
                    .as_move_value()
                    .simple_serialize()
                    .unwrap(),
                replay_protector_move_value,
                MoveValue::vector_address(txn_data.secondary_signers())
                    .simple_serialize()
                    .unwrap(),
                MoveValue::Vector(secondary_auth_keys)
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U64(txn_gas_price.into())
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U64(txn_max_gas_units.into())
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U64(txn_expiration_timestamp_secs)
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U8(chain_id.id()).simple_serialize().unwrap(),
                MoveValue::Bool(is_simulation).simple_serialize().unwrap(),
```
