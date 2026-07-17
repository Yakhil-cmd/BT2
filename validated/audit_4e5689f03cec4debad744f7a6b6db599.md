### Title
No-Timelock Global Contract Update via `GlobalContractDeployMode::AccountId` Immediately Replaces Code for All Opted-In Accounts — (File: `runtime/runtime/src/global_contracts.rs`)

---

### Summary

`DeployGlobalContractAction` with `GlobalContractDeployMode::AccountId` allows any account owner to atomically replace the Wasm code executed by every account that has opted in via `UseGlobalContractAction` with `GlobalContractIdentifier::AccountId(owner_id)`. There is no timelock, no delay, and no user-consent mechanism. The replacement takes effect on the very next `FunctionCall` to any opted-in account, giving users zero time to exit before malicious code runs against their funds.

---

### Finding Description

`GlobalContractDeployMode` has two variants:

- `CodeHash` — immutable; users reference a fixed hash.
- `AccountId` — **mutable**; the owner can replace the code at any time for all users.

The protocol documentation explicitly states:

> "Contract is deployed under the owner account id. Users will be able reference it by that account id. **This allows the owner to update the contract for all its users.**" [1](#0-0) 

When a user calls `UseGlobalContractAction` with `GlobalContractIdentifier::AccountId(owner_id)`, their account's contract field is set to `AccountContract::GlobalByAccount(owner_id)`: [2](#0-1) 

On every subsequent `FunctionCall` to that account, the runtime resolves the contract live from the trie: [3](#0-2) 

The resolution for `AccountContract::GlobalByAccount(owner_id)` performs a live trie lookup of `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(owner_id) }`: [4](#0-3) 

`action_deploy_global_contract` — the function that processes a re-deploy — performs only a balance check and immediately initiates distribution of the new code. There is no timelock, no epoch delay, and no guard preventing an owner from replacing code that is already in use: [5](#0-4) 

Validation of `DeployGlobalContractAction` checks only code size: [6](#0-5) 

**Exact corrupted value**: The Wasm code hash resolved at `TrieKey::GlobalContractCode { identifier: GlobalContractCodeIdentifier::AccountId(owner_id) }` is silently replaced with the attacker's malicious code hash. Every opted-in account's next `FunctionCall` executes the new malicious Wasm.

---

### Impact Explanation

**Critical.** Any account that has called `UseGlobalContractAction` with `GlobalContractIdentifier::AccountId(attacker_id)` will execute whatever Wasm the attacker most recently deployed under that account ID. A malicious function can transfer the account's full NEAR balance to the attacker via `promise_batch_action_transfer`, delete the account, or exfiltrate any state. The impact is proportional to the number of opted-in accounts and their balances — a popular shared contract could affect thousands of accounts simultaneously.

---

### Likelihood Explanation

**Medium.** The `AccountId` deploy mode is an intentional, documented, production feature designed for upgradeable shared contracts. Any unprivileged NEAR account can deploy a global contract with this mode, attract users with a benign initial version, and then replace it. The only barrier is the storage cost of the new deployment. No special validator or operator privilege is required.

---

### Recommendation

1. **Timelock on `AccountId`-mode re-deploys**: Require that a re-deploy under an existing `AccountId` key is announced at least N epochs (e.g., 2 epochs ≈ 24 hours on mainnet) before it takes effect. Store a pending-upgrade record in the trie; apply it only after the delay has elapsed.
2. **User opt-out window**: Emit an on-chain event (e.g., a special receipt or trie entry) when a pending upgrade is registered, so wallets and monitoring tools can alert opted-in accounts.
3. **Alternatively, deprecate mutable `AccountId` mode** and require users to re-opt-in to a new `CodeHash` after each upgrade, preserving explicit user consent.

---

### Proof of Concept

```
1. Attacker deploys benign Wasm (e.g., a staking contract) with:
      DeployGlobalContractAction { code: benign_wasm, deploy_mode: AccountId }
   → stored at TrieKey::GlobalContractCode { identifier: AccountId("attacker.near") }

2. Victims call:
      UseGlobalContractAction { contract_identifier: AccountId("attacker.near") }
   → each victim account's contract field becomes AccountContract::GlobalByAccount("attacker.near")

3. Attacker deploys malicious Wasm with:
      DeployGlobalContractAction { code: malicious_wasm, deploy_mode: AccountId }
   → action_deploy_global_contract() passes balance check, calls initiate_distribution()
   → GlobalContractDistributionReceipt propagates shard-by-shard
   → TrieKey::GlobalContractCode { identifier: AccountId("attacker.near") } now holds malicious_wasm

4. Any FunctionCall to a victim account triggers:
      RuntimeContractIdentifier::resolve(account_id, GlobalByAccount("attacker.near"), ...)
      → GlobalContractIdentifier::AccountId("attacker.near").hash(state_update, ...)
      → trie lookup returns hash of malicious_wasm  ← corrupted value
      → malicious_wasm executes, drains victim's NEAR balance
```

The `test_global_contract_update` integration test in `test-loop-tests/src/tests/global_contracts.rs` already demonstrates that a re-deploy under `AccountId` mode immediately changes the code executed by all opted-in accounts — confirming the mechanism is reachable in production: [7](#0-6)

### Citations

**File:** core/primitives/src/action/mod.rs (L133-141)
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

**File:** runtime/runtime/src/lib.rs (L631-638)
```rust
                let account_contract = account.contract().into_owned();
                let contract_id = RuntimeContractIdentifier::resolve(
                    account_id,
                    account_contract,
                    &state_update,
                    &epoch_info_provider.chain_id(),
                    AccessOptions::DEFAULT,
                )?;
```

**File:** runtime/runtime/src/contract_code.rs (L92-106)
```rust
    fn hash(self, store: &TrieUpdate, access: AccessOptions) -> Result<CryptoHash, StorageError> {
        if let GlobalContractIdentifier::CodeHash(hash) = self {
            return Ok(hash);
        }
        let key = TrieKey::GlobalContractCode { identifier: self.into() };
        let value_ref =
            store.get_ref(&key, KeyLookupMode::MemOrFlatOrTrie, access)?.ok_or_else(|| {
                let TrieKey::GlobalContractCode { identifier } = key else { unreachable!() };
                StorageError::StorageInconsistentState(format!(
                    "Global contract identifier not found {:?}",
                    identifier
                ))
            })?;
        Ok(value_ref.value_hash())
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

**File:** test-loop-tests/src/tests/global_contracts.rs (L71-106)
```rust
#[test]
fn test_global_contract_update() {
    let mut env = GlobalContractsTestEnv::setup(Balance::from_near(1000));
    let use_accounts = [env.account_shard_0.clone(), env.account_shard_1.clone()];

    env.deploy_trivial_global_contract(GlobalContractDeployMode::AccountId);

    for account in &use_accounts {
        env.use_global_contract(
            account,
            GlobalContractIdentifier::AccountId(env.deploy_account.clone()),
        );

        // Currently deployed trivial contract doesn't have any methods,
        // so we expect any function call to fail with MethodNotFound error
        let call_tx = env.call_global_contract_tx(account.clone(), account.clone());
        let call_outcome = env.execute_tx(call_tx);
        assert_matches!(
            call_outcome.status,
            FinalExecutionStatus::Failure(TxExecutionError::ActionError(ActionError {
                kind: ActionErrorKind::FunctionCallError(FunctionCallError::MethodResolveError(
                    MethodResolveError::MethodNotFound
                )),
                index: _
            }))
        );
    }

    env.deploy_global_contract(GlobalContractDeployMode::AccountId);

    for account in &use_accounts {
        // Function call should be successful after deploying rs contract
        // containing the function we call here
        env.assert_call_global_contract_success(account.clone(), account.clone());
    }
}
```
