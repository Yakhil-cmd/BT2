### Title
Unprivileged Global Contract Namespace Hijacking: `DeployGlobalContractAction` with `AccountId` Mode Missing Deployer-Receiver Identity Check — (`runtime/runtime/src/global_contracts.rs`)

### Summary

`action_deploy_global_contract` and `validate_deploy_global_contract_action` do not verify that the receipt's `predecessor_id` equals its `receiver_id` when `deploy_mode == GlobalContractDeployMode::AccountId`. Any unprivileged account can send a transaction targeting a victim account and deploy an arbitrary global contract under the victim's account-ID namespace, overwriting the victim's legitimate global contract and draining the victim's NEAR balance for storage costs.

### Finding Description

`GlobalContractDeployMode::AccountId` is designed so that the deploying account "owns" the global contract namespace keyed by its own account ID, allowing it to update the contract for all downstream users. The invariant is: only the account whose ID is used as the namespace key should be able to write to that key.

In `initiate_distribution`, the namespace key is derived unconditionally from `account_id`, which is the receipt's `receiver_id`:

```rust
// runtime/runtime/src/global_contracts.rs, lines 149-155
let id = match deploy_mode {
    GlobalContractDeployMode::CodeHash => {
        GlobalContractIdentifier::CodeHash(hash(&contract_code))
    }
    GlobalContractDeployMode::AccountId => {
        GlobalContractIdentifier::AccountId(account_id.clone())  // receiver's ID, not sender's
    }
};
```

The only validation performed on `DeployGlobalContractAction` is a code-size check:

```rust
// runtime/runtime/src/action_validation.rs, lines 226-238
fn validate_deploy_global_contract_action(
    limit_config: &LimitConfig,
    action: &DeployGlobalContractAction,
) -> Result<(), ActionsValidationError> {
    if action.code.len() as u64 > limit_config.max_contract_size {
        return Err(ActionsValidationError::ContractSizeExceeded { ... });
    }
    Ok(())
}
```

There is no check that `predecessor_id == receiver_id`. The NEAR protocol documentation explicitly lists the actions that require this identity check (`DeployContract`, `Stake`, `AddKey`, `DeleteKey`, `DeleteAccount`); `DeployGlobalContract` is absent from that list and no runtime guard compensates for the omission.

The storage cost is charged from the **receiver's** account, not the sender's:

```rust
// runtime/runtime/src/global_contracts.rs, lines 33-49
let storage_cost = apply_state.config.fees.storage_usage_config
    .global_contract_storage_amount_per_byte
    .saturating_mul(deploy_contract.code.len() as u128);
let Some(updated_balance) = account.amount().checked_sub(storage_cost) else {
    result.result = Err(ActionErrorKind::LackBalanceForState { ... });
    return Ok(());
};
account.set_amount(updated_balance);  // deducted from victim's balance
```

### Impact Explanation

**Critical.** An attacker who controls any NEAR account can:

1. **Overwrite a victim's global contract namespace**: Send a transaction with `signer_id = attacker`, `receiver_id = victim`, `Action::DeployGlobalContract { code: malicious_wasm, deploy_mode: AccountId }`. The malicious WASM is stored under `GlobalContractIdentifier::AccountId(victim)`.

2. **Corrupt all downstream accounts**: Every account that called `UseGlobalContract(GlobalContractIdentifier::AccountId(victim))` — including deterministic accounts initialized via `DeterministicStateInitAction` — now executes the attacker's code. This enables arbitrary state manipulation, fund theft, and denial of service across all such accounts.

3. **Drain the victim's balance**: The storage cost (`global_contract_storage_amount_per_byte × code_len`) is deducted from the victim's account on every successful overwrite. The attacker can repeat this to drain the victim's balance.

4. **Prevent the victim from reclaiming their namespace**: The nonce mechanism (`increment_nonce` / `check_and_update_nonce`) only prevents stale replays; a fresh deploy by the attacker always increments the nonce and wins. The victim can redeploy to increment the nonce again, but the attacker can keep racing.

### Likelihood Explanation

High. The attack requires only a standard full-access key and enough NEAR to pay gas. No special privilege, validator role, or trusted-service access is needed. The victim must have a non-zero balance to cover the storage cost, but any account that has deployed a global contract under its name necessarily has a balance. The attack is fully on-chain and deterministic.

### Recommendation

Add a `predecessor_id == receiver_id` guard in `validate_deploy_global_contract_action` (or in `action_deploy_global_contract`) when `deploy_mode == GlobalContractDeployMode::AccountId`, mirroring the existing restriction on `DeployContract`, `Stake`, `AddKey`, `DeleteKey`, and `DeleteAccount`:

```rust
// In validate_deploy_global_contract_action or action_deploy_global_contract:
if action.deploy_mode == GlobalContractDeployMode::AccountId
    && predecessor_id != receiver_id
{
    return Err(ActionsValidationError::DeployGlobalContractRequiresSelfReceiver);
}
```

For the `CodeHash` mode no such restriction is needed because the namespace key is the content hash, not the account ID.

### Proof of Concept

1. Victim account `victim.near` has deployed a legitimate global contract under its name (nonce = 1). All deterministic accounts referencing `GlobalContractIdentifier::AccountId("victim.near")` execute the legitimate code.

2. Attacker constructs and signs:
   ```
   SignedTransaction {
     signer_id:   "attacker.near",
     receiver_id: "victim.near",
     actions: [DeployGlobalContract {
       code: <malicious_wasm>,
       deploy_mode: AccountId,
     }],
   }
   ```

3. The transaction passes `validate_deploy_global_contract_action` (only size is checked). [1](#0-0) 

4. On execution, `action_deploy_global_contract` deducts storage cost from `victim.near`'s balance and calls `initiate_distribution` with `account_id = "victim.near"`. [2](#0-1) 

5. `initiate_distribution` stores the malicious code under `GlobalContractIdentifier::AccountId("victim.near")` with nonce = 2, overwriting the legitimate contract. [3](#0-2) 

6. All accounts using `GlobalContractIdentifier::AccountId("victim.near")` now execute the attacker's WASM. The victim's balance is reduced by the storage cost. The victim has no on-chain recourse other than redeploying (which the attacker can immediately overwrite again).

The missing guard is confirmed by the protocol documentation, which lists `DeployContract` but not `DeployGlobalContract` among actions requiring `predecessor_id == receiver_id`. [4](#0-3)  The validation function for `DeployGlobalContractAction` contains no identity check. [5](#0-4)  The namespace key is derived solely from the receipt's `receiver_id`, not from the sender. [6](#0-5)

### Citations

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

**File:** runtime/runtime/src/global_contracts.rs (L33-58)
```rust
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
```

**File:** runtime/runtime/src/global_contracts.rs (L149-167)
```rust
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
```

**File:** docs/RuntimeSpec/Actions.md (L26-33)
```markdown
For the following actions, `predecessor_id` and `receiver_id` are required to be equal:

- `DeployContract`
- `Stake`
- `AddKey`
- `DeleteKey`
- `DeleteAccount`

```
