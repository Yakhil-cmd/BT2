### Title
Unprotected `new` Initialization Allows Any Caller to Seize Engine Ownership and Drain Funds - (File: `engine/src/contract_methods/admin.rs`)

---

### Summary

The `new` function that initializes the Aurora Engine state performs no caller authentication. Any unprivileged NEAR account can call `new` on a deployed-but-not-yet-initialized engine instance and inject arbitrary `owner_id`, `chain_id`, and `key_manager` values. Because every subsequent privileged operation (upgrade, pause, ETH connector routing, wNEAR address, relayer keys) is gated solely on the `owner_id` stored during `new`, an attacker who wins the initialization race becomes the permanent owner and can immediately upgrade the contract to malicious bytecode, draining all user funds.

---

### Finding Description

`engine/src/contract_methods/admin.rs` `new`:

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    let input = io.read_input().to_vec();
    let args = NewCallArgs::deserialize(&input)...;
    ...
    state::set_state(&mut io, &state)?;
    Ok(())
}
```

The only guard is the already-initialized check. `env.predecessor_account_id()` is never consulted. The `env` value is used exclusively for `env.block_height()` and `env.current_account_id()` (hashchain path), never for access control.

`NewCallArgs` (all versions V1–V4) carries:
- `owner_id: AccountId` — controls every subsequent privileged call
- `chain_id: RawU256` — governs EIP-155 replay protection
- `upgrade_delay_blocks: u64` — governs how quickly an upgrade can be deployed
- `key_manager: AccountId` (V3/V4) — controls relayer key management

None of these are validated against any on-chain source of truth. An attacker supplies all of them freely.

The workspace helper `engine-workspace/src/lib.rs` `deploy_and_init` (lines 107–125) performs deployment and initialization as two separate `await` calls — two separate NEAR transactions — creating an observable window between them:

```rust
let contract = account.deploy(&self.code...).await?;   // tx 1
...
engine.new(self.chain_id, self.owner_id, ...).transact().await?;  // tx 2
```

Between tx 1 and tx 2, the engine is deployed but uninitialized. Any NEAR account that observes tx 1 can submit its own `new` call targeting the same contract account before tx 2 lands.

---

### Impact Explanation

**Critical — direct theft of all user funds.**

Once the attacker controls `owner_id`, the full privileged surface is theirs:

| Function | Effect |
|---|---|
| `stage_upgrade` / `upgrade` | Deploy arbitrary WASM to the engine account |
| `set_eth_connector_contract_account` | Redirect all ETH deposit/withdrawal flows to an attacker contract |
| `factory_set_wnear_address` | Corrupt XCC wNEAR routing |
| `pause_contract` | Permanently freeze the engine |

The attacker sets `upgrade_delay_blocks = 0` during `new`, so `stage_upgrade` followed immediately by `upgrade` deploys malicious bytecode in the same block. The malicious contract can then call `storage_write` to zero all EVM balances and redirect the ETH connector to drain bridged ETH. All EVM user balances and all bridged ETH held by the engine are at risk.

---

### Likelihood Explanation

**Medium.**

NEAR transactions are ordered within a block. An attacker monitoring the NEAR network for `DeployContract` actions targeting a known engine account ID can submit a `new` call in the next available slot before the legitimate deployer's initialization transaction. The attack requires no special privilege — only a funded NEAR account and knowledge of the target account ID (which is public). The `deploy_and_init` helper in the workspace confirms the two-step pattern is used in practice. Any deployment that does not use a single atomic NEAR batch action (combining `DeployContract` + function call to `new` in one transaction) is vulnerable.

---

### Recommendation

1. **Enforce caller identity in `new`**: Add a check that `env.predecessor_account_id() == env.current_account_id()`. In NEAR, a contract can only call itself via a batch action, so this restricts initialization to the deploying account's own batch.

```rust
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }
    // Ensure only the contract itself (via a batch deploy action) can initialize
    if env.predecessor_account_id() != env.current_account_id() {
        return Err(b"ERR_NOT_ALLOWED".into());
    }
    ...
}
```

2. **Mandate atomic deployment**: All deployment tooling must combine `DeployContract` and the `new` function call in a single NEAR batch transaction, eliminating the initialization window entirely.

---

### Proof of Concept

1. Attacker watches the NEAR network for a `DeployContract` action on the target engine account (e.g., `aurora`).
2. Attacker immediately submits a call to `new` on that account with:
   - `owner_id = "attacker.near"`
   - `upgrade_delay_blocks = 0`
   - `chain_id = <any value>`
3. If the attacker's `new` transaction lands before the deployer's `new` transaction, the engine state is set with `owner_id = "attacker.near"`. The deployer's `new` call then fails with `ERR_ALREADY_INITIALIZED`.
4. Attacker calls `stage_upgrade` with malicious WASM that, in its `state_migration` entry point, iterates all EVM storage keys and zeroes all balances, then calls the ETH connector to transfer all bridged ETH to the attacker's address.
5. Since `upgrade_delay_blocks = 0`, `internal_get_upgrade_index` returns the current block height, and `upgrade` proceeds immediately.
6. All user EVM balances and bridged ETH are drained.

**Root cause location:** [1](#0-0) 

**`owner_id` used as sole gate for all privileged operations:** [2](#0-1) 

**`upgrade` is gated only on `owner_id`:** [3](#0-2) 

**Two-step deploy+init pattern creating the window:** [4](#0-3) 

**`NewCallArgs` carrying all attacker-injectable fields:** [5](#0-4)

### Citations

**File:** engine/src/contract_methods/admin.rs (L55-88)
```rust
#[named]
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

**File:** engine-types/src/parameters/engine.rs (L76-98)
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

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NewCallArgsV3 {
    /// Chain id, according to the EIP-115 / ethereum-lists spec.
    pub chain_id: RawU256,
    /// Account which can upgrade this contract.
    /// Use empty to disable updatability.
    pub owner_id: AccountId,
    /// How many blocks after staging upgrade can deploy it.
    pub upgrade_delay_blocks: u64,
    /// Relayer keys manager.
    pub key_manager: AccountId,
}
```
