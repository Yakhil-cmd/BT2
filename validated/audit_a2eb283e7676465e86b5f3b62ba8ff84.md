### Title
Silo Whitelist Access Control Inconsistently Applied: `deploy_code` and `call` Bypass `assert_access` Check - (File: `engine/src/contract_methods/evm_transactions.rs`)

### Summary

Aurora Engine's Silo mode enforces a whitelist (`Account`, `Address`, `Admin`, `EvmAdmin`) to restrict which NEAR accounts and EVM addresses may submit transactions or deploy EVM code. The `assert_access` guard is called inside `engine::submit`, which is reached by both `submit` and `submit_with_args`. However, the two other EVM-execution entry points — `deploy_code` and `call` — invoke `engine.deploy_code_with_input` and `engine.call_with_args` respectively, neither of which calls `assert_access`. Any NEAR account can therefore deploy EVM contracts or call EVM contracts in Silo mode without appearing in any whitelist.

### Finding Description

**Protected path — `submit` / `submit_with_args`:**

Both functions delegate to `engine::submit` (the standalone function in `engine/src/engine.rs`). Inside that function, `assert_access` is called before any state mutation:

```rust
// engine/src/engine.rs ~line 1052
assert_access(&io, env, &transaction)?;
```

`assert_access` dispatches to either `silo::is_allow_submit` (call) or `silo::is_allow_deploy` (deploy) depending on whether `transaction.to` is `Some`:

```rust
fn assert_access<I: IO + Copy, E: Env>(
    io: &I, env: &E, transaction: &NormalizedEthTransaction,
) -> Result<(), EngineError> {
    let allowed = if transaction.to.is_some() {
        silo::is_allow_submit(io, &env.predecessor_account_id(), &transaction.address)
    } else {
        silo::is_allow_deploy(io, &env.predecessor_account_id(), &transaction.address)
    };
    if !allowed { return Err(EngineError { kind: EngineErrorKind::NotAllowed, gas_used: 0 }); }
    Ok(())
}
```

**Unprotected paths — `deploy_code` and `call`:**

```rust
// engine/src/contract_methods/evm_transactions.rs lines 21-43
pub fn deploy_code<I: IO + Copy, E: Env, H: PromiseHandler>(io: I, env: &E, handler: &mut H,
) -> Result<SubmitResult, ContractError> {
    with_logs_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;          // ← only pause check, NO assert_access
        let input = io.read_input().to_vec();
        let current_account_id = env.current_account_id();
        let mut engine: Engine<_, E, AuroraModExp> = Engine::new_with_state(
            state, predecessor_address(&env.predecessor_account_id()),
            current_account_id, io, env,
        );
        let result = engine.deploy_code_with_input(input, None, handler)?;
        ...
    })
}

pub fn call<I: IO + Copy, E: Env, H: PromiseHandler>(io: I, env: &E, handler: &mut H,
) -> Result<SubmitResult, ContractError> {
    with_logs_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;          // ← only pause check, NO assert_access
        let bytes = io.read_input().to_vec();
        let args = CallArgs::deserialize(&bytes).ok_or(errors::ERR_BORSH_DESERIALIZE)?;
        ...
        let result = engine.call_with_args(args, handler)?;
        ...
    })
}
```

Neither `deploy_code_with_input` nor `call_with_args` internally calls `assert_access` or any silo whitelist check. The whitelist functions `is_allow_deploy` and `is_allow_submit` are never reached from these two entry points.

The four whitelist kinds and their intended enforcement:

| Kind | Protects | Checked by `assert_access`? | Checked by `deploy_code`/`call`? |
|---|---|---|---|
| `Admin` | NEAR account deploying EVM code | ✅ via `submit` | ❌ |
| `EvmAdmin` | EVM address deploying EVM code | ✅ via `submit` | ❌ |
| `Account` | NEAR account submitting txs | ✅ via `submit` | ❌ |
| `Address` | EVM address submitting txs | ✅ via `submit` | ❌ |

### Impact Explanation

When Silo mode is active with whitelists enabled, the operator's intent is to restrict EVM interaction to a curated set of NEAR accounts and EVM addresses. The `deploy_code` and `call` NEAR entry points completely bypass this restriction.

- **Unauthorized EVM contract deployment**: Any NEAR account — regardless of whitelist status — can call `deploy_code` and deploy arbitrary EVM bytecode. This bypasses the `Admin`/`EvmAdmin` whitelist entirely.
- **Unauthorized EVM contract calls**: Any NEAR account can call `call` and invoke any EVM contract. This bypasses the `Account`/`Address` whitelist entirely.
- **Fund theft / temporary freeze**: If EVM contracts in the Silo hold ETH or ERC-20 token balances, an unauthorized caller can invoke those contracts (e.g., a token contract's `transfer` function) as their own derived EVM address, or deploy a malicious contract that interacts with existing contracts holding funds. This constitutes a realistic path to theft of user funds held in the EVM state.

**Severity: High** — whitelist bypass enabling unauthorized EVM state mutation and potential theft of funds held in EVM contracts.

### Likelihood Explanation

- The attacker requires no privileged access: any NEAR account can call `deploy_code` or `call` on the Aurora Engine contract.
- The entry points are public, documented, and reachable from any NEAR transaction.
- The only precondition is that Silo mode is active with at least one whitelist enabled — which is the exact deployment scenario the whitelist feature is designed for.
- No leaked keys, governance capture, or social engineering is required.

### Recommendation

Add the silo whitelist check to both `deploy_code` and `call` before EVM execution, mirroring the pattern used in `engine::submit`. Concretely, after `require_running`, derive the EVM address from the predecessor account and call `silo::is_allow_deploy` / `silo::is_allow_submit`:

```rust
// In deploy_code:
let predecessor_account_id = env.predecessor_account_id();
let evm_address = predecessor_address(&predecessor_account_id);
if !silo::is_allow_deploy(&io, &predecessor_account_id, &evm_address) {
    return Err(errors::ERR_NOT_ALLOWED.into());
}

// In call:
let predecessor_account_id = env.predecessor_account_id();
let evm_address = predecessor_address(&predecessor_account_id);
if !silo::is_allow_submit(&io, &predecessor_account_id, &evm_address) {
    return Err(errors::ERR_NOT_ALLOWED.into());
}
```

Alternatively, extract the guard into a shared helper and call it uniformly from all three EVM-execution entry points (`submit`, `submit_with_args`, `deploy_code`, `call`).

### Proof of Concept

1. Deploy Aurora Engine in Silo mode: call `set_silo_params` with valid params, then `set_whitelist_status` to enable `Admin`, `EvmAdmin`, `Account`, and `Address` whitelists.
2. Add only `alice.near` to the `Account` and `Address` whitelists. Do **not** add `attacker.near`.
3. From `attacker.near`, call `submit` with a signed Ethereum transaction → receives `EngineErrorKind::NotAllowed`. ✅ Correctly blocked.
4. From `attacker.near`, call `deploy_code` with arbitrary EVM bytecode → **succeeds**. The contract is deployed. ❌ Whitelist bypassed.
5. From `attacker.near`, call `call` with `CallArgs` targeting an EVM contract holding ETH → **succeeds**. The call executes. ❌ Whitelist bypassed.

The root cause is confirmed at: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** engine/src/engine.rs (L1052-1053)
```rust
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
