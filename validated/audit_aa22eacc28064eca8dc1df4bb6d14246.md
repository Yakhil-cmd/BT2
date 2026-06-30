### Title
Unprotected Initializer Allows Any Caller to Seize Engine Ownership Before Legitimate `new()` Call - (File: engine/src/contract_methods/admin.rs)

---

### Summary

The Aurora Engine's `new()` initializer performs no caller authentication. Any NEAR account that submits a `new()` call between the contract deployment transaction and the legitimate initialization transaction can set itself as `owner_id`. The owner role controls the `upgrade()` method, which can replace the entire engine WASM. An attacker who wins the race can deploy a backdoored engine that steals all bridged user funds.

---

### Finding Description

The public WASM export `new()` in `engine/src/lib.rs` delegates to `contract_methods::admin::new()`. That function's only guard is a check that state does not yet exist:

```rust
// engine/src/contract_methods/admin.rs  lines 56-88
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    let input = io.read_input().to_vec();
    let args = NewCallArgs::deserialize(&input)...;
    ...
    state::set_state(&mut io, &state)?;   // owner_id written from attacker input
    Ok(())
}
``` [1](#0-0) 

There is no call to `require_owner_only`, no `env.predecessor_account_id()` check, and no assertion that the caller is the contract account itself. The `owner_id` field is taken verbatim from the caller-supplied `NewCallArgs` input. [2](#0-1) 

The function is exported unconditionally as a public NEAR contract method:

```rust
// engine/src/lib.rs  lines 76-83
#[unsafe(no_mangle)]
pub extern "C" fn new() {
    let io = Runtime;
    let env = Runtime;
    contract_methods::admin::new(io, &env)
        .map_err(ContractError::msg)
        .sdk_unwrap();
}
``` [3](#0-2) 

In NEAR, deploying a contract and calling its initializer are two separate transactions unless the deployer explicitly batches them. If the deployer sends a `DeployContract` action and then a separate `new()` call, there is a block-level window in which any other NEAR account can submit its own `new()` transaction and have it included first.

The `NewCallArgs` variants all accept a caller-supplied `owner_id`:

```rust
// engine-types/src/parameters/engine.rs  lines 77-84
pub struct NewCallArgsV2 {
    pub chain_id: RawU256,
    pub owner_id: AccountId,   // fully attacker-controlled
    pub upgrade_delay_blocks: u64,
}
``` [4](#0-3) 

Once the attacker's `new()` succeeds, the legitimate deployer's `new()` is rejected with `ERR_ALREADY_INITIALIZED`, and the attacker holds the `owner_id` role.

---

### Impact Explanation

`owner_id` is the sole gating identity for the `upgrade()` method:

```rust
// engine/src/contract_methods/admin.rs  lines 174-176
pub fn upgrade<I, E, H>(...) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    require_owner_only(&state, &env.predecessor_account_id())?;
``` [5](#0-4) 

`upgrade()` issues a NEAR batch that replaces the entire engine WASM with attacker-supplied code:

```rust
actions: vec![
    PromiseAction::DeployContract { code },          // arbitrary WASM
    PromiseAction::FunctionCall { name: "state_migration", ... },
],
``` [6](#0-5) 

The Aurora Engine holds all bridged ETH and ERC-20 balances for every user on the Aurora EVM. A backdoored WASM can redirect any `submit` or `call` to drain those balances, constituting **direct theft of all user funds at rest** — a Critical impact.

The owner can also call `pause_contract()` to permanently freeze withdrawals before deploying the backdoor, constituting **permanent freezing of funds**. [7](#0-6) 

---

### Likelihood Explanation

NEAR does not enforce atomic deploy+init at the protocol level. The workspace helper `deploy_and_init` in `engine-workspace/src/lib.rs` issues `account.deploy(...)` and then `engine.new(...)` as two separate async calls, demonstrating that the two-step pattern is the natural usage: [8](#0-7) 

An attacker monitoring the NEAR chain for a `DeployContract` action targeting a new Aurora Engine account can immediately submit a `new()` call with their own `owner_id`. Because NEAR block producers order transactions within a chunk, and because the attacker's transaction can be submitted with a higher priority or simply in the same block before the deployer's second transaction, the race is realistic. The attack requires no special privilege — only a funded NEAR account and knowledge of the deployment event.

---

### Recommendation

1. **Enforce caller identity in `new()`**: Add a check that `env.predecessor_account_id() == env.current_account_id()`. This restricts initialization to a self-call, which can only originate from a batch that also contains the `DeployContract` action.

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    // Ensure initialization can only happen atomically with deployment
    if env.predecessor_account_id() != env.current_account_id() {
        return Err(b"ERR_UNAUTHORIZED".into());
    }
    ...
}
```

2. **Alternatively**, mandate that deployment and initialization are always performed in a single NEAR batch action (`DeployContract` + `FunctionCall { name: "new", ... }`), and document this as a hard requirement enforced by the contract itself.

---

### Proof of Concept

**Step 1 — Attacker observes a `DeployContract` action targeting a new `aurora` account on NEAR.**

**Step 2 — Attacker immediately submits:**
```
near call aurora new \
  '{"chain_id": [0,0,...,1], "owner_id": "attacker.near", "upgrade_delay_blocks": 0}' \
  --accountId attacker.near
```
This call reaches `new()` before the legitimate deployer's initialization transaction. Because `state::get_state(&io)` returns `Err` (no state yet), the guard passes and `owner_id` is written as `attacker.near`.

**Step 3 — Legitimate deployer's `new()` call arrives and is rejected with `ERR_ALREADY_INITIALIZED`.**

**Step 4 — Attacker calls `upgrade()` with a malicious WASM that, on any `submit` call, transfers the caller's EVM balance to the attacker's address:**
```
near call aurora upgrade <malicious_wasm_bytes> --accountId attacker.near
```

**Step 5 — All subsequent user transactions on Aurora execute the backdoored engine. The attacker drains all bridged ETH and ERC-20 balances.**

Root cause confirmed at:
- `engine/src/contract_methods/admin.rs` lines 56–88 — no caller check in `new()`
- `engine/src/lib.rs` lines 76–83 — unconditional public export of `new()`
- `engine/src/contract_methods/admin.rs` lines 169–206 — `upgrade()` gated solely on `owner_id` [1](#0-0) [3](#0-2) [5](#0-4)

### Citations

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

**File:** engine/src/contract_methods/admin.rs (L169-206)
```rust
pub fn upgrade<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    require_owner_only(&state, &env.predecessor_account_id())?;

    let input = io.read_input().to_vec();
    let (code, state_migration_gas) = match UpgradeParams::try_from_slice(&input) {
        Ok(args) => (
            args.code,
            args.state_migration_gas
                .map_or(GAS_FOR_STATE_MIGRATION, NearGas::new),
        ),
        Err(_) => (input, GAS_FOR_STATE_MIGRATION), // Backward compatibility
    };

    let target_account_id = env.current_account_id();
    let batch = PromiseBatchAction {
        target_account_id,
        actions: vec![
            PromiseAction::DeployContract { code },
            PromiseAction::FunctionCall {
                name: "state_migration".to_string(),
                args: vec![],
                attached_yocto: ZERO_YOCTO,
                gas: state_migration_gas,
            },
        ],
    };
    let promise_id = handler.promise_create_batch(&batch);

    handler.promise_return(promise_id);

    Ok(())
}
```

**File:** engine/src/contract_methods/admin.rs (L251-260)
```rust
pub fn pause_contract<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        require_running(&state)?;
        state.is_paused = true;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
```

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

**File:** engine-types/src/parameters/engine.rs (L76-85)
```rust
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NewCallArgsV2 {
    /// Chain id, according to the EIP-115 / ethereum-lists spec.
    pub chain_id: RawU256,
    /// Account which can upgrade this contract.
    /// Use empty to disable updatability.
    pub owner_id: AccountId,
    /// How many blocks after staging upgrade can deploy it.
    pub upgrade_delay_blocks: u64,
}
```

**File:** engine-workspace/src/lib.rs (L107-126)
```rust
        let contract = account
            .deploy(
                &self
                    .code
                    .ok_or_else(|| anyhow::anyhow!("WASM wasn't set"))?,
            )
            .await?;
        let engine = EngineContract {
            account,
            contract,
            public_key,
            node,
        };

        engine
            .new(self.chain_id, self.owner_id, self.upgrade_delay_blocks)
            .transact()
            .await
            .map_err(|e| anyhow::anyhow!("Error while initialize aurora contract: {e}"))?;

```
