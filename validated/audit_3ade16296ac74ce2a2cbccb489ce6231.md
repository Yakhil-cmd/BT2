### Title
Missing Access Control on `deploy_erc20_token` Allows Unauthorized ERC-20 Token Deployment - (File: engine/src/contract_methods/connector.rs)

---

### Summary

The `deploy_erc20_token` function in `engine/src/contract_methods/connector.rs` performs no caller authentication. Any unprivileged NEAR account can invoke it to deploy an ERC-20 mirror token for any NEP-141 token. The code's own comment explicitly states the function should only be callable by the owner, but no such enforcement exists.

---

### Finding Description

`deploy_erc20_token` (line 112) only calls `require_running` and then proceeds unconditionally to deploy an ERC-20 token mapped to a caller-supplied NEP-141 account ID:

```rust
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;   // ← only check
        let bytes = io.read_input().to_vec();
        let args = DeployErc20TokenArgs::deserialize(&bytes)...;
        match args {
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;
                ...
            }
            DeployErc20TokenArgs::WithMetadata(nep141) => {
                ...
                // Safe because these promises are read-only calls to the main engine contract
                // and this transaction could be executed by the owner of the contract only.
                let promise_args = PromiseWithCallbackArgs { base, callback };
``` [1](#0-0) 

The comment at lines 148–149 explicitly acknowledges the intent that only the owner should call this function, but no `require_owner_only` guard is present. Compare this with `mirror_erc20_token` (line 456), which correctly enforces `require_owner_only`: [2](#0-1) 

The `require_owner_only` helper is defined and used throughout the codebase for exactly this purpose: [3](#0-2) 

The WASM entrypoint `deploy_erc20_token` in `lib.rs` passes no additional guard before delegating to this function: [4](#0-3) 

---

### Impact Explanation

The NEP-141 ↔ ERC-20 mapping is a one-time, write-once registry. Once an ERC-20 address is mapped to a NEP-141 token ID, the engine uses that mapping for all subsequent bridging operations. An attacker who front-runs a legitimate `deploy_erc20_token` call with the same NEP-141 token ID can:

1. Register an ERC-20 address for a NEP-141 token before the owner does, with attacker-chosen parameters.
2. Permanently block the owner from creating the correct mapping for that token (duplicate-mapping protection prevents re-registration).
3. Cause all future `ft_on_transfer` calls for that NEP-141 token to credit the wrong ERC-20 contract, or cause them to fail entirely.

This constitutes **permanent freezing of bridged funds** for the affected NEP-141 token: users who bridge that token into Aurora will receive tokens in an incorrect or inaccessible ERC-20 contract, with no recovery path short of a contract upgrade.

**Impact: Critical — Permanent freezing of funds.**

---

### Likelihood Explanation

- The function is a public NEAR contract method callable by any NEAR account with no deposit, no token holding, and no prior relationship with the contract.
- The attacker only needs to know the NEP-141 account ID of a token that has not yet been registered — trivially discoverable by watching the NEAR blockchain.
- Front-running on NEAR is straightforward: an attacker monitors the mempool or watches for the owner's pending transaction and submits their own call first.
- No special tooling is required beyond a standard NEAR CLI or SDK call.

**Likelihood: High.**

---

### Recommendation

Add `require_owner_only` immediately after `require_running` in `deploy_erc20_token`, mirroring the pattern used in `mirror_erc20_token`:

```rust
pub fn deploy_erc20_token<...>(...) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;  // ← add this
        ...
    })
}
```

If a broader set of callers (e.g., a deployer role) should be permitted in the future, introduce a dedicated role following the principle of least privilege, consistent with the `WhitelistKind::Admin` / `WhitelistKind::EvmAdmin` role model already present in the Silo subsystem. [5](#0-4) 

---

### Proof of Concept

**Preconditions:** Aurora Engine is running (`is_paused = false`). A NEP-141 token `token.near` has not yet been registered.

**Attack steps:**

1. Attacker observes (via NEAR RPC or mempool monitoring) that the Aurora owner is about to call `deploy_erc20_token` for `token.near`.
2. Attacker submits their own NEAR transaction calling `deploy_erc20_token` on the Aurora Engine contract with `DeployErc20TokenArgs::Legacy("token.near")` before the owner's transaction is finalized.
3. Because `deploy_erc20_token` has no caller check, the NEAR runtime accepts and executes the attacker's call. An ERC-20 address is minted and the NEP-141 → ERC-20 mapping is written to engine storage.
4. The owner's subsequent `deploy_erc20_token` call for `token.near` fails because the mapping already exists.
5. All `ft_on_transfer` calls for `token.near` now route to the attacker-initiated ERC-20 contract. Users bridging `token.near` into Aurora receive tokens in the wrong contract. The correct ERC-20 can never be registered without a full contract upgrade.

### Citations

**File:** engine/src/contract_methods/connector.rs (L112-159)
```rust
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let bytes = io.read_input().to_vec();
        let args =
            DeployErc20TokenArgs::deserialize(&bytes).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

        match args {
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;

                io.return_output(
                    &borsh::to_vec(address.as_bytes()).map_err(|_| errors::ERR_SERIALIZE)?,
                );
                Ok(PromiseOrValue::Value(address))
            }
            DeployErc20TokenArgs::WithMetadata(nep141) => {
                let args = borsh::to_vec(&nep141).map_err(|_| errors::ERR_SERIALIZE)?;
                let base = PromiseCreateArgs {
                    target_account_id: nep141,
                    method: "ft_metadata".to_string(),
                    args: vec![],
                    attached_balance: ZERO_YOCTO,
                    attached_gas: READ_PROMISE_ATTACHED_GAS,
                };
                let callback = PromiseCreateArgs {
                    target_account_id: env.current_account_id(),
                    method: "deploy_erc20_token_callback".to_string(),
                    args,
                    attached_balance: ZERO_YOCTO,
                    attached_gas: DEPLOY_ERC20_TOKEN_CALLBACK_ATTACHED_GAS,
                };
                // Safe because these promises are read-only calls to the main engine contract
                // and this transaction could be executed by the owner of the contract only.
                let promise_args = PromiseWithCallbackArgs { base, callback };
                let promise_id = handler.promise_create_with_callback(&promise_args);

                handler.promise_return(promise_id);

                Ok(PromiseOrValue::Promise(promise_args))
            }
        }
    })
}
```

**File:** engine/src/contract_methods/connector.rs (L456-463)
```rust
pub fn mirror_erc20_token<I: IO + Env + Copy, H: PromiseHandler>(
    io: I,
    handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    // TODO: Add an admin access list of accounts allowed to do it.
    require_owner_only(&state, &io.predecessor_account_id())?;
```

**File:** engine/src/contract_methods/mod.rs (L79-87)
```rust
pub fn require_owner_only(
    state: &state::EngineState,
    predecessor_account_id: &AccountId,
) -> Result<(), ContractError> {
    if &state.owner_id != predecessor_account_id {
        return Err(errors::ERR_NOT_ALLOWED.into());
    }
    Ok(())
}
```

**File:** engine/src/lib.rs (L613-621)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn deploy_erc20_token() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::deploy_erc20_token(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine-types/src/parameters/silo.rs (L65-80)
```rust
pub enum WhitelistKind {
    /// The whitelist of this type is for storing NEAR accounts. Accounts stored in this whitelist
    /// have an admin role. The admin role allows to add new admins and add new entities
    /// (`AccountId` and `Address`) to whitelists. Also, this role allows to deploy of EVM code
    /// and submit transactions.
    Admin = 0x0,
    /// The whitelist of this type is for storing EVM addresses. Addresses included in this
    /// whitelist can deploy EVM code.
    EvmAdmin = 0x1,
    /// The whitelist of this type is for storing NEAR accounts. Accounts included in this
    /// whitelist can submit transactions.
    Account = 0x2,
    /// The whitelist of this type is for storing EVM addresses. Addresses included in this
    /// whitelist can submit transactions.
    Address = 0x3,
}
```
