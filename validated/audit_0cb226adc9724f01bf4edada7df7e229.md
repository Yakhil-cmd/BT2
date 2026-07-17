### Title
Unauthorized Overwrite of `AccountId`-Mode Global Contract via Cross-Contract Call Enables Arbitrary Code Execution for All Opted-In Users - (File: runtime/runtime/src/global_contracts.rs)

### Summary

`action_deploy_global_contract` in `global_contracts.rs` performs no predecessor-identity check when `GlobalContractDeployMode::AccountId` is used. Any deployed contract can create a cross-contract call targeting victim account B and append a `DeployGlobalContract(AccountId)` action, overwriting the global contract stored under B's account ID. Every account that has called `UseGlobalContract(AccountId(B))` will subsequently execute the attacker's code.

### Finding Description

When `DeployGlobalContractAction` is processed with `GlobalContractDeployMode::AccountId`, `initiate_distribution` derives the global-contract identifier directly from the receipt's `account_id` (the receiver):

```rust
GlobalContractDeployMode::AccountId => {
    GlobalContractIdentifier::AccountId(account_id.clone())
}
``` [1](#0-0) 

`action_deploy_global_contract` only checks that the receiver has enough balance to cover storage; it never verifies that the action's predecessor equals the receiver:

```rust
pub(crate) fn action_deploy_global_contract(
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,
    ...
    let Some(updated_balance) = account.amount().checked_sub(storage_cost) else { ... };
    ...
    initiate_distribution(state_update, account_id.clone(), ...)?;
``` [2](#0-1) 

The host function `promise_batch_action_deploy_global_contract_by_account_id` lets any contract append this action to a promise targeting an arbitrary account:

```rust
pub fn promise_batch_action_deploy_global_contract_by_account_id(
    ctx: &mut Ctx, memory: &mut [u8],
    promise_idx: u64, code_len: u64, code_ptr: u64,
) -> Result<()> {
    promise_batch_action_deploy_global_contract_impl(
        ctx, memory, promise_idx, code_len, code_ptr,
        GlobalContractDeployMode::AccountId, ...
    )
}
``` [3](#0-2) 

Action validation (`validate_deploy_global_contract_action`) only checks code size; it imposes no restriction on which predecessor may include this action in a receipt:

```rust
fn validate_deploy_global_contract_action(
    limit_config: &LimitConfig,
    action: &DeployGlobalContractAction,
) -> Result<(), ActionsValidationError> {
    validate_global_contract_code(limit_config, &action.code)?;
    Ok(())
}
``` [4](#0-3) 

The dispatch in `lib

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

**File:** runtime/runtime/src/action_validation.rs (L240-246)
```rust
fn validate_use_global_contract_action(
    action: &UseGlobalContractAction,
) -> Result<(), ActionsValidationError> {
    validate_global_contract_identifier(&action.contract_identifier)?;

    Ok(())
}
```
