### Title
`action_deploy_global_contract` burns full storage cost on every `AccountId`-mode redeploy without refunding the previous deployment's cost — (`runtime/runtime/src/global_contracts.rs`)

### Summary

`GlobalContractDeployMode::AccountId` is explicitly designed to allow the owner to update a global contract for all its users. However, `action_deploy_global_contract` charges and permanently burns the full storage cost (`global_contract_storage_amount_per_byte × new_code_size`) on every redeploy, without refunding the storage cost paid for the previous deployment. Because the old code is overwritten in the trie (not added alongside it), the deployer is permanently overcharged for storage that no longer exists.

### Finding Description

In `action_deploy_global_contract`, the storage cost is computed and burned unconditionally:

```rust
let storage_cost = apply_state
    .config
    .fees
    .storage_usage_config
    .global_contract_storage_amount_per_byte
    .saturating_mul(deploy_contract.code.len() as u128);
// ...
result.tokens_burnt =
    result.tokens_burnt.checked_add(storage_cost).ok_or(IntegerOverflowError)?;
account.set_amount(updated_balance);
``` [1](#0-0) 

There is no check for whether a contract already exists at the `AccountId` identifier, and no refund of the previous deployment's storage cost.

When the `GlobalContractDistributionReceipt` is later applied in `apply_distribution_current_shard`, the old code is silently overwritten:

```rust
let trie_key = TrieKey::GlobalContractCode { identifier };
state_update.set(trie_key, global_contract_data.code().to_vec());
``` [2](#0-1) 

The old code bytes are gone from the trie, but the NEAR tokens burned for them are not recoverable. The `AccountId` deploy mode is explicitly documented as supporting updates: [3](#0-2) 

The parameter name `global_contract_storage_amount_per_byte` and the error `LackBalanceForState` (not a "deployment fee" error) both indicate the charge is intended to represent the cost of occupying storage, not a one-time deployment fee. The documentation confirms: *"LackBalanceForState if the account does not hold enough NEAR to cover the added storage."* [4](#0-3) 

The word "added" implies the charge should be incremental (new size minus old size), not the full new size.

### Impact Explanation

After N redeployments with `AccountId` mode, the deployer has burned:

```
total_burned = Σ(code_size_i × rate)  for i = 1..N
actual_storage_cost = code_size_N × rate
overcharge = Σ(code_size_i × rate)  for i = 1..N-1
```

At `global_contract_storage_amount_per_byte = 0.0001 NEAR/byte` (from protocol config version 77), a single redeploy of a 4 MB contract (the maximum allowed size) results in a permanent loss of **400 NEAR** for storage that no longer exists. This loss compounds with each subsequent redeploy. [5](#0-4) 

### Likelihood Explanation

Any account that uses `GlobalContractDeployMode::AccountId` and subsequently updates their contract is affected. This is an explicitly supported and documented use case (the entire purpose of `AccountId` mode is to allow updates). The attacker-controlled input is the `DeployGlobalContractAction` with `AccountId` mode, which requires no special privileges — any account with sufficient balance can submit it.

### Recommendation

Before charging the storage cost, read the existing contract size at the `AccountId` trie key. If a contract already exists, either:

1. Refund the old storage cost and charge the new storage cost in full, or
2. Charge only the net difference: `(new_size - old_size) × rate` (and refund if the new contract is smaller).

This requires reading the existing value length from the trie before overwriting, which is already done in analogous places such as `clear_account_contract_storage_usage`. [6](#0-5) 

### Proof of Concept

1. Account `alice.near` deploys a global contract with `AccountId` mode, code size = 1,000,000 bytes.
   - Burns: `1,000,000 × 0.0001 = 100 NEAR`
2. Alice redeploys with `AccountId` mode, code size = 2,000,000 bytes.
   - Burns: `2,000,000 × 0.0001 = 200 NEAR`
   - Old 1,000,000-byte code is overwritten in the trie.
3. Total burned: **300 NEAR**. Actual storage occupied: 2,000,000 bytes = **200 NEAR** worth.
4. Alice has permanently lost **100 NEAR** for storage that no longer exists, with no mechanism for recovery since `tokens_burnt` is not refundable.

### Citations

**File:** runtime/runtime/src/global_contracts.rs (L33-49)
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
```

**File:** runtime/runtime/src/global_contracts.rs (L208-211)
```rust
    let trie_key = TrieKey::GlobalContractCode { identifier };
    let code_len = global_contract_data.code().len() as u64;
    state_update.set(trie_key, global_contract_data.code().to_vec());
    state_update.commit(StateChangeCause::ReceiptProcessing { receipt_hash: receipt.get_hash() });
```

**File:** core/primitives/src/action/mod.rs (L138-142)
```rust
    /// Contract is deployed under the owner account id.
    /// Users will be able reference it by that account id.
    /// This allows the owner to update the contract for all its users.
    AccountId,
}
```

**File:** docs/RuntimeSpec/Actions.md (L464-466)
```markdown
**Execution Error**:

- `LackBalanceForState` if the account does not hold enough NEAR to cover the added storage.
```

**File:** core/parameters/res/runtime_configs/77.yaml (L2-2)
```yaml
global_contract_storage_amount_per_byte: { old: 999999999999999999999999999 yN, new: 0.0001 N }
```

**File:** runtime/runtime/src/actions.rs (L412-419)
```rust
pub(crate) fn clear_account_contract_storage_usage(
    state_update: &TrieUpdate,
    account_id: &AccountId,
    account: &mut Account,
) -> Result<(), StorageError> {
    let contract_storage = get_contract_storage_usage(state_update, account_id, account)?;
    account.set_storage_usage(account.storage_usage().saturating_sub(contract_storage));
    Ok(())
```
