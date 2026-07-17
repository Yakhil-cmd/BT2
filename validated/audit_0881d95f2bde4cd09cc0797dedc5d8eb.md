### Title
Unprivileged Contract Can Overwrite Any Account's Global Contract Under `AccountId` Mode — (`runtime/runtime/src/global_contracts.rs`)

### Summary

When `DeployGlobalContractAction` is executed with `deploy_mode = AccountId`, the runtime stores the supplied code under the **receipt receiver's** account ID as the global-contract namespace key, with no check that the receipt was authorized by that account's owner. Any unprivileged contract can create a cross-contract promise targeting an arbitrary victim account and attach a `DeployGlobalContractAction { mode: AccountId }` to it. The runtime will then overwrite the victim's global-contract entry with attacker-supplied code, affecting every account that references the victim's global contract via `GlobalContractIdentifier::AccountId`.

### Finding Description

**Root cause — `initiate_distribution` uses the receipt receiver as the namespace key without an ownership check.**

In `action_deploy_global_contract` (`runtime/runtime/src/global_contracts.rs` lines 23–61), the only guard is a balance check on the receiver account:

```rust
let Some(updated_balance) = account.amount().checked_sub(storage_cost) else {
    result.result = Err(ActionErrorKind::LackBalanceForState { ... });
    return Ok(());
};
``` [1](#0-0) 

After that check passes, `initiate_distribution` is called with `account_id` (the receipt receiver) and the attacker-supplied `deploy_mode`:

```rust
GlobalContractDeployMode::AccountId => {
    GlobalContractIdentifier::AccountId(account_id.clone())
}
``` [2](#0-1) 

The resulting `GlobalContractDistributionReceipt` propagates the attacker's code to every shard and writes it to `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }`, overwriting whatever the legitimate owner had previously deployed.

**Attacker-controlled entry point — the promise API.**

A malicious contract calls:
1. `promise_batch_create("victim.near")` — creates a receipt targeting the victim.
2. `promise_batch_action_deploy_global_contract_by_account_id(promise_idx, code_len, code_ptr)` — attaches `DeployGlobalContractAction { mode: AccountId }` with attacker-chosen code. [3](#0-2) 

Neither the promise API nor the action validator imposes any restriction on which account the promise targets or whether the deployer owns that account:

```rust
Action::DeployGlobalContract(a) => validate_deploy_global_contract_action(limit_config, a),
``` [4](#0-3) 

`validate_deploy_global_contract_action` only checks code size: [5](#0-4) 

**Nonce does not protect against this attack.** The nonce mechanism (`check_and_update_nonce`) is designed to prevent *stale* re-delivery of the same distribution receipt across shards. A fresh deployment always carries a freshly incremented nonce that is ≥ the stored nonce, so it always succeeds:

```rust
if incoming_nonce < stored_nonce {
    return Ok(false);
}
``` [6](#0-5) 

An attacker's fresh deployment will have a nonce higher than the victim's last deployment and will unconditionally overwrite the stored code.

**Corrupted value.** The trie entry `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId("victim.near") }` is set to attacker-controlled bytes. Every account whose `AccountContract` is `GlobalByAccount("victim.near")` will subsequently execute the attacker's code. [7](#0-6) 

### Impact Explanation

Every account that previously called `UseGlobalContract(AccountId("victim.near"))` now executes attacker-controlled WASM on every function call. The attacker's code runs with the full host API of the calling account: it can drain that account's balance via `promise_batch_action_transfer`, add or delete access keys, deploy new contracts, or corrupt arbitrary storage. Because global contracts are shared across all shards, the blast radius is every account on every shard that references the victim's account-ID global contract. This is an unauthorized, persistent code-identity substitution with direct asset-theft potential — **Critical** impact.

### Likelihood Explanation

The attack requires only:
1. A deployed contract on any account (no privilege).
2. A cross-contract call to the victim (standard NEAR operation).
3. The victim account to hold enough balance to cover the storage cost of a minimal WASM binary (a few bytes × `global_contract_storage_amount_per_byte`).

Most accounts that have deployed a global contract hold well above the minimum balance. The attack is repeatable and can be sustained to prevent the victim from reclaiming their namespace. **Medium-High** likelihood.

### Recommendation

In `action_deploy_global_contract`, when `deploy_mode == AccountId`, assert that the receipt's predecessor (the caller) is the same as the receipt receiver (the account whose ID will be used as the namespace key). Concretely, pass the `predecessor_id` from the receipt into the function and add:

```rust
if deploy_contract.deploy_mode == GlobalContractDeployMode::AccountId
    && predecessor_id != account_id
{
    result.result = Err(ActionErrorKind::ActorNoPermission {
        account_id: account_id.clone(),
        actor_id: predecessor_id.clone(),
    }.into());
    return Ok(());
}
```

Alternatively, restrict `DeployGlobalContractAction { mode: AccountId }` to self-receipts only (i.e., `signer_id == receiver_id`) at the action-validation layer, analogous to how `DeployContract` is implicitly self-scoped in practice.

### Proof of Concept

1. Attacker deploys `attacker.near` with a contract containing:
   ```rust
   pub fn hijack_global_contract() {
       let victim = "victim.near";
       let idx = promise_batch_create(victim);
       // minimal valid WASM that steals balance on every call
       let malicious_wasm: &[u8] = &[...];
       promise_batch_action_deploy_global_contract_by_account_id(
           idx, malicious_wasm.len() as u64, malicious_wasm.as_ptr() as u64
       );
   }
   ```
2. `victim.near` has previously deployed a legitimate global contract via `DeployGlobalContractAction { mode: AccountId }` and many accounts reference it with `UseGlobalContract(AccountId("victim.near"))`.
3. Attacker calls `attacker.near::hijack_global_contract()`.
4. The runtime executes the resulting receipt on `victim.near`'s shard. `action_deploy_global_contract` passes the balance check (victim has funds), calls `initiate_distribution("victim.near", malicious_wasm, AccountId)`, and the distribution receipt propagates to all shards.
5. `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }` is now set to the attacker's WASM on every shard.
6. The next function call to any account using `GlobalContractIdentifier::AccountId("victim.near")` executes the attacker's code with that account's full permissions. [8](#0-7) [9](#0-8)

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

**File:** runtime/runtime/src/global_contracts.rs (L141-168)
```rust
fn initiate_distribution(
    state_update: &mut TrieUpdate,
    account_id: AccountId,
    contract_code: Arc<[u8]>,
    deploy_mode: &GlobalContractDeployMode,
    current_shard_id: ShardId,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let id = match deploy_mode {
        GlobalContractDeployMode::CodeHash => {
            GlobalContractIdentifier::CodeHash(hash(&contract_code))
        }
        GlobalContractDeployMode::AccountId => {
            GlobalContractIdentifier::AccountId(account_id.clone())
        }
    };
    // Increment the nonce and write it to state immediately to prevent multiple
    // distributions with the same nonce from being initiated. This requires
    // allowing the same nonce in the freshness check when applying the
    // distribution receipt.
    let nonce = increment_nonce(state_update, &id)?;
    let distribution_receipt =
        GlobalContractDistributionReceipt::new(id, current_shard_id, vec![], contract_code, nonce);
    let distribution_receipts =
        Receipt::new_global_contract_distribution(account_id, distribution_receipt);
    // No need to set receipt_id here, it will be generated as part of apply_action_receipt
    result.new_receipts.push(distribution_receipts);
    Ok(())
```

**File:** runtime/runtime/src/global_contracts.rs (L207-211)
```rust
    let config = apply_state.config.wasm_config.clone();
    let trie_key = TrieKey::GlobalContractCode { identifier };
    let code_len = global_contract_data.code().len() as u64;
    state_update.set(trie_key, global_contract_data.code().to_vec());
    state_update.commit(StateChangeCause::ReceiptProcessing { receipt_hash: receipt.get_hash() });
```

**File:** runtime/runtime/src/global_contracts.rs (L250-252)
```rust
    if incoming_nonce < stored_nonce {
        return Ok(false);
    }
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L2558-2571)
```rust
    pub fn promise_batch_action_deploy_global_contract_by_account_id(
        &mut self,
        promise_idx: u64,
        code_len: u64,
        code_ptr: u64,
    ) -> Result<()> {
        self.promise_batch_action_deploy_global_contract_impl(
            promise_idx,
            code_len,
            code_ptr,
            GlobalContractDeployMode::AccountId,
            "promise_batch_action_deploy_global_contract_by_account_id",
        )
    }
```

**File:** runtime/runtime/src/action_validation.rs (L139-139)
```rust
        Action::DeployGlobalContract(a) => validate_deploy_global_contract_action(limit_config, a),
```

**File:** runtime/runtime/src/action_validation.rs (L226-237)
```rust
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
```
