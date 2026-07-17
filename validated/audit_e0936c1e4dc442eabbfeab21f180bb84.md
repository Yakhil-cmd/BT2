### Title
Unrestricted Cross-Contract `DeployGlobalContract(AccountId)` Overwrites Any Account's Global Contract Namespace — (File: `runtime/runtime/src/global_contracts.rs`)

### Summary

`action_deploy_global_contract` contains no authorization check when `deploy_mode == GlobalContractDeployMode::AccountId`. Any contract can create a cross-contract promise targeting a victim account and attach a `DeployGlobalContractAction` with `AccountId` mode, overwriting the victim's global contract namespace. Every account that has called `UseGlobalContract(AccountId(victim))` will subsequently execute the attacker's injected code.

### Finding Description

`GlobalContractDeployMode::AccountId` is documented as "allows the owner to update the contract for all its users." The trie key written is `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(account_id) }`, where `account_id` is the receipt's `receiver_id`. [1](#0-0) 

In `initiate_distribution`, the identifier is derived solely from `account_id` (the receipt receiver), with no check that the receipt's `predecessor_id` equals `receiver_id`: [2](#0-1) 

The VM host function `promise_batch_action_deploy_global_contract_by_account_id` allows any executing contract to attach a `DeployGlobalContract(AccountId)` action to a promise targeting **any** account: [3](#0-2) 

The `sir` (self-is-receiver) flag computed inside is used only for gas pricing, not for access control. The action validation layer only checks contract size: [4](#0-3) 

The execution dispatch in `lib.rs` passes `account_id` (the receiver) directly to `action_deploy_global_contract` with no predecessor equality check: [5](#0-4) 

### Impact Explanation

**Corrupted value:** `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(victim_account_id) }` — the global contract bytecode stored under the victim's namespace is silently replaced with attacker-controlled code.

Every account that previously called `UseGlobalContract(AccountId(victim))` stores `AccountContract::GlobalByAccount(victim_account_id)` in its account record. On the next function call to any such account, the runtime resolves the contract through the now-poisoned trie key and executes the attacker's code. The attacker can drain balances, corrupt storage, or exfiltrate data from all affected accounts in a single overwrite. [6](#0-5) 

### Likelihood Explanation

The attack requires only a deployed contract with sufficient gas budget. The attacker:
1. Deploys a contract at account B.
2. From B's contract, calls `promise_batch_create(victim_account_id)` then `promise_batch_action_deploy_global_contract_by_account_id(promise_idx, malicious_wasm)`.
3. The resulting receipt executes on victim account A, deducting storage cost from A's balance and writing attacker code under `GlobalContractCodeIdentifier::AccountId(A)`.
4. All accounts using `GlobalContractIdentifier::AccountId(A)` now execute malicious code.

The only prerequisite is that A has enough balance to cover `global_contract_storage_amount_per_byte * code_len`. If A is a legitimate global-contract deployer it will have this balance. No validator or privileged role is required. [7](#0-6) 

### Recommendation

In `action_deploy_global_contract`, when `deploy_mode == GlobalContractDeployMode::AccountId`, assert that the receipt's `predecessor_id` equals `receiver_id` (i.e., the action is self-directed). Alternatively, enforce this at the action-validation layer in `validate_deploy_global_contract_action` by threading the predecessor through and rejecting cross-account `AccountId`-mode deployments.

### Proof of Concept

```
// Attacker contract (deployed at attacker.near)
#[near_bindgen]
impl Attacker {
    pub fn overwrite_victim(&self) {
        // victim.near has deployed a global contract under AccountId mode
        // and many accounts use GlobalContractIdentifier::AccountId("victim.near")
        let malicious_wasm: Vec<u8> = include_bytes!("malicious.wasm").to_vec();

        // Create a promise targeting victim.near
        let promise = env::promise_batch_create("victim.near");

        // Attach DeployGlobalContract(AccountId) — no authorization check exists
        env::promise_batch_action_deploy_global_contract_by_account_id(
            promise,
            &malicious_wasm,
        );
        // Receipt executes on victim.near:
        //   account_id = "victim.near"
        //   TrieKey::GlobalContractCode { AccountId("victim.near") } <- malicious_wasm
        // All accounts using GlobalContractIdentifier::AccountId("victim.near")
        // now execute malicious_wasm on their next function call.
    }
}
``` [8](#0-7) [9](#0-8)

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

**File:** runtime/runtime/src/global_contracts.rs (L74-106)
```rust
pub(crate) fn use_global_contract(
    state_update: &mut TrieUpdate,
    account_id: &AccountId,
    account: &mut Account,
    contract_identifier: &GlobalContractIdentifier,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let key = TrieKey::GlobalContractCode { identifier: contract_identifier.clone().into() };
    if !state_update.contains_key(&key, AccessOptions::DEFAULT)? {
        result.result = Err(ActionErrorKind::GlobalContractDoesNotExist {
            identifier: contract_identifier.clone(),
        }
        .into());
        return Ok(());
    }
    clear_account_contract_storage_usage(state_update, account_id, account)?;
    if account.contract().is_local() {
        state_update.remove(TrieKey::ContractCode { account_id: account_id.clone() });
    }
    let contract = match contract_identifier {
        GlobalContractIdentifier::CodeHash(code_hash) => AccountContract::Global(*code_hash),
        GlobalContractIdentifier::AccountId(id) => AccountContract::GlobalByAccount(id.clone()),
    };
    account.set_storage_usage(
        account.storage_usage().checked_add(contract_identifier.len() as u64).ok_or_else(|| {
            StorageError::StorageInconsistentState(format!(
                "Storage usage integer overflow for account {}",
                account_id
            ))
        })?,
    );
    account.set_contract(contract);
    Ok(())
```

**File:** runtime/runtime/src/global_contracts.rs (L141-156)
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

**File:** runtime/runtime/src/lib.rs (L593-604)
```rust
            Action::DeployGlobalContract(deploy_global_contract) => {
                metrics::ACTION_CALLED_COUNT.deploy_global_contract.inc();
                let account = account.as_mut().expect(EXPECT_ACCOUNT_EXISTS);
                action_deploy_global_contract(
                    state_update,
                    account,
                    account_id,
                    apply_state,
                    deploy_global_contract,
                    &mut result,
                )?;
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
