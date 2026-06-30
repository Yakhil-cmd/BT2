### Title
Unguarded `new` Initialization Allows Any Caller to Seize Contract Ownership and Drain Bridged ETH — (`engine/src/contract_methods/admin.rs`)

---

### Summary

The Aurora Engine's `new` contract method, which initializes all critical engine state including the `owner_id`, performs no caller-identity check. Any NEAR account that races the deployer to call `new` first can install itself as the contract owner. The owner role controls `attach_full_access_key`, `upgrade`, and `stage_upgrade`, making a successful race equivalent to full contract takeover and enabling direct theft of all bridged ETH held by the engine account.

---

### Finding Description

The public WASM export `new()` in `engine/src/lib.rs` delegates unconditionally to `contract_methods::admin::new`: [1](#0-0) 

The implementation in `admin.rs` guards only against a *second* call (already-initialized), but applies **no check on who the caller is**: [2](#0-1) 

Specifically, lines 57-58 are the sole guard:

```rust
if state::get_state(&io).is_ok() {
    return Err(b"ERR_ALREADY_INITIALIZED".into());
}
```

There is no `require_owner_only`, no `predecessor_account_id` check, and no deployer whitelist. The `NewCallArgs` deserialized from input includes `owner_id` (confirmed in `engine-types/src/parameters/engine.rs`). Whoever calls `new` first writes that `owner_id` into the engine state via `state::set_state`. [3](#0-2) 

Every other sensitive admin function — `set_owner`, `upgrade`, `stage_upgrade`, `attach_full_access_key`, `pause_contract` — is correctly gated behind `require_owner_only`: [4](#0-3) 

But that gate is meaningless if the attacker already controls `owner_id`.

---

### Impact Explanation

**Critical — Direct theft of all user funds (bridged ETH) and permanent contract takeover.**

Once the attacker is `owner_id`, the most direct path to fund theft is `attach_full_access_key`: [5](#0-4) 

This function adds a full-access key to the Aurora Engine NEAR account. A full-access key allows the holder to sign *any* transaction on behalf of the contract account — including transferring all NEAR/ETH balances, deleting the account, or deploying arbitrary replacement code. All ETH bridged through the connector is held in this account's balance. The attacker can drain it entirely.

Alternatively, the attacker can call `upgrade` to deploy arbitrary WASM, achieving the same outcome.

---

### Likelihood Explanation

**Low-to-medium likelihood, but the window is real and the attack is atomic.**

On NEAR, contract deployment and the first method call are separate transactions. An attacker watching the chain for a newly deployed Aurora Engine contract (identifiable by its account ID, e.g. `aurora`) can submit a `new` call in the same block or the immediately following block before the deployer's initialization transaction is included. NEAR's transaction ordering within a block is not guaranteed to favor the deployer. The attack requires only a single successful transaction and no ongoing presence — once `new` is called with the attacker's `owner_id`, the state is permanently set and the deployer's own `new` call will fail with `ERR_ALREADY_INITIALIZED`.

---

### Recommendation

Add a deployer/predecessor check at the top of `admin::new` before any state is written. The simplest correct fix is to require that the caller is the contract account itself (i.e., `current_account_id == predecessor_account_id`, which is the NEAR convention for "called during deployment") or to require the predecessor matches a hardcoded or constructor-time deployer address:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    // Add: only the contract account itself may initialize (NEAR deployment convention)
    if env.current_account_id() != env.predecessor_account_id() {
        return Err(b"ERR_NOT_ALLOWED".into());
    }
    // ... rest of initialization
}
``` [6](#0-5) 

---

### Proof of Concept

1. Attacker monitors NEAR for a newly deployed contract at account `aurora` (or any Aurora Engine account ID).
2. Attacker immediately submits a NEAR transaction calling `new` on that account with `NewCallArgs { owner_id: "attacker.near", chain_id: <any valid>, ... }`.
3. If the attacker's transaction is included before the deployer's `new` call, `state::set_state` writes `owner_id = "attacker.near"` into storage.
4. The deployer's subsequent `new` call returns `ERR_ALREADY_INITIALIZED` and fails.
5. Attacker calls `attach_full_access_key` (gated only by `require_owner_only`, which now passes for `"attacker.near"`) to add their NEAR key as a full-access key on the engine account.
6. Attacker uses that full-access key to transfer all bridged ETH balances out of the engine account. [1](#0-0) [2](#0-1) [5](#0-4)

### Citations

**File:** engine/src/lib.rs (L76-83)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn new() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::new(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine/src/contract_methods/admin.rs (L56-88)
```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }

    let input = io.read_input().to_vec();
    let args = NewCallArgs::deserialize(&input).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

    let initial_hashchain = args.initial_hashchain();
    let state: EngineState = args.into();

    if let Some(block_hashchain) = initial_hashchain {
        let block_height = env.block_height();
        let mut hashchain = Hashchain::new(
            state.chain_id,
            env.current_account_id(),
            block_height,
            block_hashchain,
        );

        hashchain.add_block_tx(
            block_height,
            function_name!(),
            &input,
            &[],
            &Bloom::default(),
        )?;
        crate::hashchain::save_hashchain(&mut io, &hashchain)?;
    }

    state::set_state(&mut io, &state)?;
    Ok(())
}
```

**File:** engine/src/contract_methods/admin.rs (L483-513)
```rust
pub fn attach_full_access_key<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;

    require_running(&state)?;
    require_owner_only(&state, &env.predecessor_account_id())?;

    let public_key = serde_json::from_slice::<FullAccessKeyArgs>(&io.read_input().to_vec())
        .map(|args| args.public_key)
        .map_err(|_| errors::ERR_JSON_DESERIALIZE)?;
    let current_account_id = env.current_account_id();
    let action = PromiseAction::AddFullAccessKey {
        public_key,
        nonce: 0, // not actually used - depends on block height
    };
    let promise = PromiseBatchAction {
        target_account_id: current_account_id,
        actions: vec![action],
    };
    // SAFETY: This action is dangerous because it adds a new full access key (FAK) to the Engine account.
    // However, it is safe to do so here because of the `require_owner_only` check above; only the
    // (trusted) owner account can add a new FAK.
    let promise_id = handler.promise_create_batch(&promise);

    handler.promise_return(promise_id);

    Ok(())
}
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
