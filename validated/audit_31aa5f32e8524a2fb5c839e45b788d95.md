### Title
Unauthorized Global Contract Overwrite via Cross-Contract Promise in `AccountId` Deploy Mode — (`runtime/runtime/src/global_contracts.rs`)

### Summary

`action_deploy_global_contract` stores a global contract under the receipt receiver's `account_id` when `GlobalContractDeployMode::AccountId` is used, with no check that the action was authorized by the account owner. Any deployed contract can create a batch promise to an arbitrary victim account and append a `DeployGlobalContract(AccountId)` action, overwriting the victim's global contract identifier with attacker-controlled code. Storage cost is charged to the victim's balance, and every account that previously called `UseGlobalContract(AccountId(victim))` will subsequently execute the injected code.

### Finding Description

`GlobalContractDeployMode::AccountId` is designed so that the deploying account can update the global contract stored under its own account ID. The invariant is: only the account whose ID is used as the identifier should be able to write to `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(account_id) }`.

In `action_deploy_global_contract`, the identifier is derived directly from `account_id`, which is the receipt's **receiver** — not the original transaction signer: [1](#0-0) 

There is no guard verifying that the receipt was initiated by the account owner. The only validation in `validate_deploy_global_contract_action` is a code-size check: [2](#0-1) 

The host function `promise_batch_action_deploy_global_contract_by_account_id` allows any executing contract to append this action to a batch promise targeting **any** account: [3](#0-2) 

The attack path:

1. Attacker deploys a contract on their own account.
2. Attacker's contract calls `promise_batch_create("victim.near")` and appends `DeployGlobalContract(AccountId)` with malicious WASM.
3. The resulting receipt executes on `victim.near`'s shard. `account_id = "victim.near"`, so the identifier becomes `GlobalContractIdentifier::AccountId("victim.near")`.
4. Storage cost is deducted from `victim.near`'s balance (not the attacker's).
5. `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }` is overwritten with the malicious code.
6. All accounts that previously called `UseGlobalContract(AccountId("victim.near"))` now hold `AccountContract::GlobalByAccount("victim.near")`, which resolves to the attacker's code at execution time. [4](#0-3) 

The nonce mechanism (`check_and_update_nonce`) only prevents **stale** distribution receipts from overwriting a newer version; it does not prevent an unauthorized initial overwrite: [5](#0-4) 

### Impact Explanation

**Global contract/code selection integrity is broken.** An unprivileged attacker can:

- Inject arbitrary WASM into the global contract slot of any victim account, causing all downstream users of that contract to execute attacker-controlled code (fund theft, state corruption, denial of service).
- Force the victim to pay storage costs (up to `4 MiB × global_contract_storage_amount_per_byte`) for the malicious deployment, draining the victim's balance.

The corrupted trie key is `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(victim) }`.

### Likelihood Explanation

Any account with a deployed contract and the `global_contract_host_fns` feature enabled can execute this attack. The only precondition is that the victim account exists and holds enough balance to cover the storage cost. No privileged access is required. The attack is a single cross-contract call.

### Recommendation

In `action_deploy_global_contract`, when `deploy_mode == GlobalContractDeployMode::AccountId`, verify that the receipt's `predecessor_id` equals `account_id` (i.e., the action was sent by the account itself, not by a third-party contract):

```rust
if deploy_contract.deploy_mode == GlobalContractDeployMode::AccountId {
    if receipt.predecessor_id() != account_id {
        result.result = Err(ActionErrorKind::ActorNoPermission {
            account_id: account_id.clone(),
            actor_id: receipt.predecessor_id().clone(),
        }.into());
        return Ok(());
    }
}
```

Alternatively, restrict `DeployGlobalContract(AccountId)` so it can only appear in a receipt where `signer_id == receiver_id` (self-call), mirroring the restriction already applied to other privileged self-only actions.

### Proof of Concept

```rust
// Attacker's contract method
pub fn attack(&mut self, victim: AccountId) {
    // Create a batch promise targeting the victim account
    let promise = env::promise_batch_create(&victim);
    // Append DeployGlobalContract(AccountId) with malicious WASM
    env::promise_batch_action_deploy_global_contract_by_account_id(
        promise,
        &MALICIOUS_WASM_BYTES,
    );
}
```

After this executes:
- `TrieKey::GlobalContractCode { identifier: AccountId(victim) }` contains the malicious WASM.
- Storage cost is charged to `victim`'s balance.
- Every account with `AccountContract::GlobalByAccount(victim)` now runs the malicious code on the next function call. [6](#0-5) [7](#0-6)

### Citations

**File:** runtime/runtime/src/global_contracts.rs (L23-61)
```rust
pub(crate) fn action_deploy_global_contract(
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,
    apply_state: &ApplyState,
    deploy_contract: &DeployGlobalContractAction,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let _span = tracing::debug_span!(target: "runtime", "action_deploy_global_contract").entered();

    let storage_cost = apply_state
        .config
        .fees
        .storage_usage_config
        .global_contract_storage_amount_per_byte
        .saturating_mul(deploy_contract.code.len() as u128);
    let Some(updated_balance) = account.amount().checked_sub(storage_cost) else {
        result.result = Err(ActionErrorKind::LackBalanceForState {
            account_id: account_id.clone(),
            amount: storage_cost,
        }
        .into());
        return Ok(());
    };
    result.tokens_burnt =
        result.tokens_burnt.checked_add(storage_cost).ok_or(IntegerOverflowError)?;
    account.set_amount(updated_balance);

    initiate_distribution(
        state_update,
        account_id.clone(),
        deploy_contract.code.clone(),
        &deploy_contract.deploy_mode,
        apply_state.shard_id,
        result,
    )?;

    Ok(())
}
```

**File:** runtime/runtime/src/global_contracts.rs (L149-156)
```rust
    let id = match deploy_mode {
        GlobalContractDeployMode::CodeHash => {
            GlobalContractIdentifier::CodeHash(hash(&contract_code))
        }
        GlobalContractDeployMode::AccountId => {
            GlobalContractIdentifier::AccountId(account_id.clone())
        }
    };
```

**File:** runtime/runtime/src/global_contracts.rs (L189-211)
```rust
fn apply_distribution_current_shard(
    receipt: &Receipt,
    global_contract_data: &GlobalContractDistributionReceipt,
    apply_state: &ApplyState,
    state_update: &mut TrieUpdate,
) -> Result<Compute, RuntimeError> {
    let identifier = match &global_contract_data.id() {
        GlobalContractIdentifier::CodeHash(hash) => GlobalContractCodeIdentifier::CodeHash(*hash),
        GlobalContractIdentifier::AccountId(account_id) => {
            GlobalContractCodeIdentifier::AccountId(account_id.clone())
        }
    };

    let is_nonce_fresh = check_and_update_nonce(global_contract_data, &identifier, state_update)?;
    if !is_nonce_fresh {
        return Ok(0);
    }

    let config = apply_state.config.wasm_config.clone();
    let trie_key = TrieKey::GlobalContractCode { identifier };
    let code_len = global_contract_data.code().len() as u64;
    state_update.set(trie_key, global_contract_data.code().to_vec());
    state_update.commit(StateChangeCause::ReceiptProcessing { receipt_hash: receipt.get_hash() });
```

**File:** runtime/runtime/src/global_contracts.rs (L238-256)
```rust
fn check_and_update_nonce(
    global_contract_data: &GlobalContractDistributionReceipt,
    identifier: &GlobalContractCodeIdentifier,
    state_update: &mut TrieUpdate,
) -> Result<bool, RuntimeError> {
    let nonce_key = TrieKey::GlobalContractNonce { identifier: identifier.clone() };
    let stored_nonce = get_nonce(state_update, &nonce_key)?;
    let incoming_nonce = global_contract_data.nonce();

    // Allow the same nonce since the nonce is updated immediately when
    // initiating distribution to prevent multiple distributions with the same
    // nonce from being initiated.
    if incoming_nonce < stored_nonce {
        return Ok(false);
    }

    set_nonce(state_update, nonce_key, incoming_nonce);
    Ok(true)
}
```

**File:** runtime/runtime/src/action_validation.rs (L225-238)
```rust
/// Validates `DeployGlobalContractAction`. Checks that the given contract size doesn't exceed the limit.
fn validate_deploy_global_contract_action(
    limit_config: &LimitConfig,
    action: &DeployGlobalContractAction,
) -> Result<(), ActionsValidationError> {
    if action.code.len() as u64 > limit_config.max_contract_size {
        return Err(ActionsValidationError::ContractSizeExceeded {
            size: action.code.len() as u64,
            limit: limit_config.max_contract_size,
        });
    }

    Ok(())
}
```

**File:** runtime/near-vm-runner/src/wasmtime_runner/logic.rs (L2671-2687)
```rust
pub fn promise_batch_action_deploy_global_contract_by_account_id(
    ctx: &mut Ctx,
    memory: &mut [u8],
    promise_idx: u64,
    code_len: u64,
    code_ptr: u64,
) -> Result<()> {
    promise_batch_action_deploy_global_contract_impl(
        ctx,
        memory,
        promise_idx,
        code_len,
        code_ptr,
        GlobalContractDeployMode::AccountId,
        "promise_batch_action_deploy_global_contract_by_account_id",
    )
}
```

**File:** core/primitives/src/action/mod.rs (L133-142)
```rust
pub enum GlobalContractDeployMode {
    /// Contract is deployed under its code hash.
    /// Users will be able reference it by that hash.
    /// This effectively makes the contract immutable.
    CodeHash,
    /// Contract is deployed under the owner account id.
    /// Users will be able reference it by that account id.
    /// This allows the owner to update the contract for all its users.
    AccountId,
}
```
