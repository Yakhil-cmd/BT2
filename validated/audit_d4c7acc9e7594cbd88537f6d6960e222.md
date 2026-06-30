### Title
Silo Mode Whitelist Bypass via `call` and `deploy_code` Methods - (`engine/src/contract_methods/evm_transactions.rs`)

### Summary

In Silo Mode, the `call` and `deploy_code` NEAR-native entry points do not perform any Silo whitelist check, while the `submit` and `submit_with_args` paths correctly enforce the whitelist via `assert_access`. Any unprivileged NEAR account can bypass the Silo access control model entirely by using `call` or `deploy_code` instead of `submit`.

### Finding Description

Aurora Engine's Silo Mode enforces access control through four whitelists: `Admin` and `EvmAdmin` (for code deployment) and `Account` and `Address` (for transaction submission). The `assert_access` function in `engine/src/engine.rs` enforces these checks, but it is only called from the `submit_with_alt_modexp` path.

The `submit` and `submit_with_args` entrypoints correctly call `engine::submit`, which calls `assert_access`: [1](#0-0) 

`assert_access` checks both the NEAR `predecessor_account_id` against the `Account`/`Admin` whitelist and the EVM `transaction.address` against the `Address`/`EvmAdmin` whitelist: [2](#0-1) 

However, the `call` entrypoint in `engine/src/contract_methods/evm_transactions.rs` constructs an `Engine` and calls `engine.call_with_args` directly, with **no whitelist check**: [3](#0-2) 

Similarly, `deploy_code` constructs an `Engine` and calls `engine.deploy_code_with_input` directly, with **no whitelist check**: [4](#0-3) 

The `call_with_args` method itself also performs no whitelist check: [5](#0-4) 

The NEAR-level entrypoints `call()` and `deploy_code()` in `engine/src/lib.rs` are publicly callable by any NEAR account: [6](#0-5) 

### Impact Explanation

When a Silo operator enables the `Account`, `Address`, `Admin`, and `EvmAdmin` whitelists to restrict who may submit transactions or deploy contracts, any NEAR account not on those whitelists can still:

1. **Call any EVM contract** by invoking the `call` method with arbitrary `CallArgs`, using a NEAR-derived EVM address as the origin.
2. **Deploy arbitrary EVM bytecode** by invoking the `deploy_code` method.

This completely undermines the Silo access control model. If the restricted EVM contracts hold user funds or implement privileged logic, an unauthorized caller can interact with them freely, potentially leading to direct theft of funds held in EVM contracts or unauthorized state changes.

### Likelihood Explanation

The `call` and `deploy_code` methods are standard, documented NEAR-callable entrypoints on the Aurora Engine contract. Any NEAR account can call them permissionlessly. A Silo operator who enables whitelists to restrict access has no way to prevent this bypass without additional off-chain measures. The likelihood is high whenever Silo Mode is deployed with whitelists enabled.

### Recommendation

Add a Silo whitelist check at the start of both `call` and `deploy_code` in `engine/src/contract_methods/evm_transactions.rs`, analogous to the `assert_access` call in `submit_with_alt_modexp`. For `call`, check the `Account` and `Address` whitelists using `silo::is_allow_submit`. For `deploy_code`, check the `Admin` and `EvmAdmin` whitelists using `silo::is_allow_deploy`. The EVM address to check against the `Address`/`EvmAdmin` whitelist should be `predecessor_address(&env.predecessor_account_id())`, which is already computed in both functions.

### Proof of Concept

1. Deploy Aurora Engine in Silo Mode.
2. Enable all four whitelists via `set_whitelists_statuses`.
3. Do **not** add attacker's NEAR account to any whitelist.
4. Confirm that calling `submit` with a signed Ethereum transaction from the attacker's EVM address returns `EngineErrorKind::NotAllowed` (as tested in `engine-tests/src/tests/silo.rs`). [7](#0-6) 

5. Now call the `call` method directly from the attacker's NEAR account with `CallArgs` targeting any EVM contract. The call succeeds — no whitelist check is performed.
6. Similarly, call `deploy_code` from the attacker's NEAR account with arbitrary EVM bytecode. The deployment succeeds.

The root cause is that `assert_access` is never invoked in the `call` or `deploy_code` code paths, while it is correctly invoked in `submit_with_alt_modexp`: [8](#0-7)

### Citations

**File:** engine/src/engine.rs (L583-620)
```rust
    pub fn call_with_args<P: PromiseHandler>(
        &mut self,
        args: CallArgs,
        handler: &mut P,
    ) -> EngineResult<SubmitResult> {
        let origin = Address::new(self.origin());
        match args {
            CallArgs::V2(call_args) => {
                let contract = call_args.contract;
                let value = call_args.value.into();
                let input = call_args.input;
                self.call(
                    &origin,
                    &contract,
                    value,
                    input,
                    u64::MAX,
                    Vec::new(),
                    Vec::new(),
                    handler,
                )
            }
            CallArgs::V1(call_args) => {
                let contract = call_args.contract;
                let value = Wei::zero();
                let input = call_args.input;
                self.call(
                    &origin,
                    &contract,
                    value,
                    input,
                    u64::MAX,
                    Vec::new(),
                    Vec::new(),
                    handler,
                )
            }
        }
```

**File:** engine/src/engine.rs (L1051-1052)
```rust
    // Check if the sender has rights to submit transactions or deploy code.
    assert_access(&io, env, &transaction)?;
```

**File:** engine/src/engine.rs (L1756-1765)
```rust
fn assert_access<I: IO + Copy, E: Env>(
    io: &I,
    env: &E,
    transaction: &NormalizedEthTransaction,
) -> Result<(), EngineError> {
    let allowed = if transaction.to.is_some() {
        silo::is_allow_submit(io, &env.predecessor_account_id(), &transaction.address)
    } else {
        silo::is_allow_deploy(io, &env.predecessor_account_id(), &transaction.address)
    };
```

**File:** engine/src/contract_methods/silo/mod.rs (L130-138)
```rust
/// Check if a user has the right to deploy EVM code.
pub fn is_allow_deploy<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_account_allowed_deploy(io, account) && is_address_allowed_deploy(io, address)
}

/// Check if a user has the right to submit transactions.
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}
```

**File:** engine/src/contract_methods/evm_transactions.rs (L21-43)
```rust
pub fn deploy_code<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<SubmitResult, ContractError> {
    with_logs_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let input = io.read_input().to_vec();
        let current_account_id = env.current_account_id();
        let mut engine: Engine<_, E, AuroraModExp> = Engine::new_with_state(
            state,
            predecessor_address(&env.predecessor_account_id()),
            current_account_id,
            io,
            env,
        );
        let result = engine.deploy_code_with_input(input, None, handler)?;
        let result_bytes = borsh::to_vec(&result).map_err(|_| errors::ERR_SERIALIZE)?;
        io.return_output(&result_bytes);
        Ok(result)
    })
}
```

**File:** engine/src/contract_methods/evm_transactions.rs (L46-71)
```rust
pub fn call<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<SubmitResult, ContractError> {
    with_logs_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let bytes = io.read_input().to_vec();
        let args = CallArgs::deserialize(&bytes).ok_or(errors::ERR_BORSH_DESERIALIZE)?;
        let current_account_id = env.current_account_id();
        let predecessor_account_id = env.predecessor_account_id();

        let mut engine: Engine<_, E, AuroraModExp> = Engine::new_with_state(
            state,
            predecessor_address(&predecessor_account_id),
            current_account_id,
            io,
            env,
        );
        let result = engine.call_with_args(args, handler)?;
        let result_bytes = borsh::to_vec(&result).map_err(|_| errors::ERR_SERIALIZE)?;
        io.return_output(&result_bytes);
        Ok(result)
    })
}
```

**File:** engine/src/lib.rs (L252-270)
```rust
    pub extern "C" fn deploy_code() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::evm_transactions::deploy_code(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Call method on the EVM contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn call() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::evm_transactions::call(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine-tests/src/tests/silo.rs (L483-486)
```rust
    let err = runner
        .submit_transaction(&signer.secret_key, transaction.clone())
        .unwrap_err();
    assert_eq!(err.kind, EngineErrorKind::NotAllowed);
```
