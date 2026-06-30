### Title
Silo Whitelist Bypassed via `deploy_code` and `call` Direct NEAR Entry Points - (File: engine/src/contract_methods/evm_transactions.rs)

### Summary
The Aurora Engine silo whitelist system is designed to restrict which NEAR accounts and EVM addresses may deploy EVM contracts or execute EVM transactions. However, the `deploy_code` and `call` NEAR-callable entry points perform no whitelist check, allowing any NEAR account to bypass the `Admin`/`EvmAdmin` and `Account`/`Address` whitelists entirely.

### Finding Description

The silo module exposes four whitelist kinds:
- `WhitelistKind::Admin` / `WhitelistKind::EvmAdmin` — restrict who may deploy EVM bytecode
- `WhitelistKind::Account` / `WhitelistKind::Address` — restrict who may submit EVM transactions [1](#0-0) 

The whitelist enforcement is implemented in `assert_access`, which is called only from `engine::submit_with_alt_modexp` — the path taken by the `submit` and `submit_with_args` NEAR entry points. [2](#0-1) [3](#0-2) 

However, the `deploy_code` entry point only checks `require_running` and never calls `assert_access` or any silo whitelist function: [4](#0-3) 

Likewise, the `call` entry point only checks `require_running`: [5](#0-4) 

Both are exposed as public NEAR contract methods: [6](#0-5) 

### Impact Explanation

When a silo operator enables the `Admin`/`EvmAdmin` whitelist to restrict EVM contract deployment, or the `Account`/`Address` whitelist to restrict EVM transaction execution, any unprivileged NEAR account can still:

1. Call `deploy_code` directly to deploy arbitrary EVM bytecode, bypassing the `Admin`/`EvmAdmin` whitelist.
2. Call `call` directly to execute arbitrary EVM contract calls, bypassing the `Account`/`Address` whitelist.

The attacker's EVM origin is derived from their NEAR predecessor account ID via `predecessor_address`, so they act as their own EVM address. This allows them to interact with any EVM contract — including transferring their own EVM-held assets, calling contracts with side effects, or deploying malicious contracts — in a silo environment that is supposed to be access-controlled. The entire silo access control model is undermined.

**Impact class:** High — whitelist bypass enabling unauthorized EVM code deployment and execution; depending on silo contract state, this can escalate to direct fund movement.

### Likelihood Explanation

Any NEAR account can call `deploy_code` or `call` on the Aurora engine contract at any time. No special privileges, leaked keys, or social engineering are required. The attacker only needs to know the Aurora engine contract account ID, which is public. Likelihood is high whenever a silo operator has enabled the whitelists.

### Recommendation

Add silo whitelist checks to `deploy_code` and `call` analogous to the `assert_access` call in `submit_with_alt_modexp`. Specifically:

- In `deploy_code`, call `silo::is_allow_deploy(io, &env.predecessor_account_id(), &predecessor_address(&env.predecessor_account_id()))` and return `ERR_NOT_ALLOWED` if it returns `false`.
- In `call`, call `silo::is_allow_submit(io, &env.predecessor_account_id(), &predecessor_address(&env.predecessor_account_id()))` and return `ERR_NOT_ALLOWED` if it returns `false`. [1](#0-0) 

### Proof of Concept

1. Operator deploys Aurora engine in silo mode, enables all whitelists via `set_whitelists_statuses`, and does **not** add the attacker's NEAR account or EVM address to any whitelist.
2. Attacker calls `submit` with a signed Ethereum deploy transaction → rejected with `EngineErrorKind::NotAllowed` (whitelist enforced via `assert_access`).
3. Attacker calls `deploy_code` directly with raw EVM bytecode as input → **succeeds**, contract is deployed. No whitelist check is performed.
4. Attacker calls `call` with `CallArgs` targeting any EVM contract → **succeeds**. No whitelist check is performed.

The whitelist that the silo operator configured is completely bypassed via the `deploy_code` and `call` entry points. [7](#0-6) [3](#0-2)

### Citations

**File:** engine/src/contract_methods/silo/mod.rs (L130-143)
```rust
/// Check if a user has the right to deploy EVM code.
pub fn is_allow_deploy<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_account_allowed_deploy(io, account) && is_address_allowed_deploy(io, address)
}

/// Check if a user has the right to submit transactions.
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}

/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

**File:** engine/src/engine.rs (L1049-1052)
```rust
    let fixed_gas = silo::get_fixed_gas(&io);

    // Check if the sender has rights to submit transactions or deploy code.
    assert_access(&io, env, &transaction)?;
```

**File:** engine/src/engine.rs (L1756-1775)
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

    if !allowed {
        return Err(EngineError {
            kind: EngineErrorKind::NotAllowed,
            gas_used: 0,
        });
    }

    Ok(())
}
```

**File:** engine/src/contract_methods/evm_transactions.rs (L20-71)
```rust
#[named]
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

#[named]
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

**File:** engine/src/lib.rs (L251-270)
```rust
    #[unsafe(no_mangle)]
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
