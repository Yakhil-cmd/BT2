### Title
Unprivileged Cross-Account Global Contract Overwrite via `DeployGlobalContractAction(AccountId mode)` — (File: `runtime/runtime/src/global_contracts.rs`)

### Summary
Any deployed contract can create a cross-contract promise targeting an arbitrary victim account with `DeployGlobalContractAction { deploy_mode: GlobalContractDeployMode::AccountId }`. When executed, the runtime stores the attacker-supplied WASM under `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(victim_account_id) }`, silently overwriting the victim's global contract. Every account that previously called `UseGlobalContract(AccountId(victim))` will subsequently execute the attacker's code. No authorization check exists anywhere in the validation or execution path.

### Finding Description

`GlobalContractDeployMode::AccountId` is documented as allowing the "owner" to update a global contract for all its users. The identifier used to store the code is the receipt's `receiver_id`, derived inside `initiate_distribution`: [1](#0-0) 

The `account_id` passed to `initiate_distribution` is the receipt's `receiver_id`, not the signer or predecessor: [2](#0-1) 

The host function `promise_batch_action_deploy_global_contract_by_account_id` accepts any `promise_idx`, including promises targeting accounts other than the current contract. The `sir` (self-is-receiver) flag is computed but used only for gas pricing, not for authorization: [3](#0-2) 

The action validator `validate_deploy_global_contract_action` checks only code size — no ownership or predecessor check: [4](#0-3) 

The execution handler `action_deploy_global_contract` likewise performs no check that the receipt's predecessor equals the receiver: [5](#0-4) 

**Attack path:**
1. Attacker deploys a malicious contract on `attacker.near`.
2. Attacker calls their contract, which calls `promise_batch_create("victim.near")` then `promise_batch_action_deploy_global_contract_by_account_id(promise_idx, malicious_code_len, malicious_code_ptr)`.
3. The resulting receipt is executed on `victim.near`: `action_deploy_global_contract` is called with `account_id = "victim.near"`.
4. `initiate_distribution` stores the malicious code under `GlobalContractCodeIdentifier::AccountId("victim.near")` with a freshly incremented nonce (higher than the victim's previous nonce), so `check_and_update_nonce` accepts it: [6](#0-5) 

5. The storage cost is deducted from `victim.near`'s balance (not the attacker's).
6. All accounts whose `AccountContract` is `GlobalByAccount("victim.near")` now execute the attacker's code on the next function call.

### Impact Explanation

- **Code identity corruption**: The trie value at `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }` is replaced with attacker-controlled WASM.
- **Cascading execution hijack**: Every account that called `UseGlobalContract(AccountId("victim.near"))` runs the attacker's code on the next invocation — the corrupted `AccountContract::GlobalByAccount` pointer is resolved at call time: [7](#0-6) 

- **Balance drain**: The storage cost for the malicious code is charged to `victim.near`, not the attacker.
- Scope: **global contract/code selection** — exact corrupted state value is `TrieKey::GlobalContractCode { identifier: AccountId(victim) }`.

### Likelihood Explanation

Any unprivileged account that can deploy a contract (a standard NEAR capability requiring only gas and a small balance) can execute this attack. No validator, operator, or admin privilege is required. The attack is a single cross-contract call transaction.

### Recommendation

In `action_deploy_global_contract` (or in `validate_deploy_global_contract_action` for the `AccountId` mode), add a check that the receipt's `predecessor_id` equals the `receiver_id` before allowing `GlobalContractDeployMode::AccountId`. Alternatively, restrict `DeployGlobalContractAction(AccountId mode)` to self-receipts only (i.e., require `sir == true` in the host function), mirroring the ownership semantics described in the documentation.

### Proof of Concept

```rust
// Attacker's contract (deployed on attacker.near)
#[near_bindgen]
pub fn overwrite_victim_global_contract() {
    // Create a promise targeting victim.near
    let promise = env::promise_batch_create("victim.near");
    // Append DeployGlobalContractByAccountId with malicious WASM
    // This stores malicious_code under GlobalContractCode[AccountId("victim.near")]
    env::promise_batch_action_deploy_global_contract_by_account_id(
        promise,
        &MALICIOUS_WASM,
    );
}
```

After this executes:
- `TrieKey::GlobalContractCode { identifier: AccountId("victim.near") }` contains `MALICIOUS_WASM`
- All accounts with `AccountContract::GlobalByAccount("victim.near")` execute the attacker's code on the next function call
- `victim.near`'s balance is reduced by `global_contract_storage_amount_per_byte * MALICIOUS_WASM.len()`

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

**File:** runtime/runtime/src/global_contracts.rs (L93-105)
```rust
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
