## Confirmed Finding: `remove_account` charges compute only for gas-key nonces, not for regular access keys removed

### Title
Unbounded, unpriced compute cost when deleting an account with many regular access keys - (File: `core/store/src/utils/mod.rs`, `runtime/runtime/src/actions.rs`)

### Summary
`action_delete_account` in `runtime/runtime/src/actions.rs` charges a fixed base fee (`delete_account_cost`, a constant ~147 Ggas) for the `DeleteAccount` action, plus explicit compute accounting only for **gas-key nonces** removed. It never accounts for the compute cost of removing an account's regular (non-gas) access keys, even though `remove_account` iterates over and deletes every single one of them.

### Finding Description
`remove_account` (`core/store/src/utils/mod.rs:487-557`) walks the trie prefix for all access keys of an account and, for every entry found, either queues a gas-key-nonce removal or a regular-access-key removal (`core/store/src/utils/mod.rs:497-535`). It returns a `RemoveAccountResult` that **only** tracks `gas_key_nonce_count` / `gas_key_nonce_total_key_bytes` [1](#0-0) ; there is no counter for the number of ordinary `AccessKey` entries removed.

In `action_delete_account` (`runtime/runtime/src/actions.rs:299-375`), after calling `remove_account`, the only compute that gets added to `result.compute_usage` is derived from `remove_result.gas_key_nonce_count` via `storage_removes_compute` [2](#0-1) . Regular access keys removed by the same call are completely unaccounted for in gas/compute terms — the sender only ever pays the fixed `delete_account_cost` fee regardless of how many regular access keys exist on the account [3](#0-2) .

By contrast, deleting a single gas key via `DeleteKeyAction` correctly meters compute proportional to the number of nonces removed (`delete_gas_key`, `runtime/runtime/src/access_keys.rs:93-134`), showing the codebase is aware that per-key removal must be priced — but this metering was not extended to cover the bulk regular-access-key removal path inside `remove_account`/`action_delete_account`.

This is structurally the same bug class as the DepositQueue issue: an unprivileged action (`AddKey`, which any account can call on itself, each individually gas-metered and cheap) can be used to accumulate an arbitrarily large number of trie entries under one account, and a single later unprivileged action (`DeleteAccount`) then performs O(n) trie iteration + n `state_update.remove()` calls while being charged a constant, size-independent fee.

### Impact Explanation
An attacker can add a very large number of regular `AddKey` actions to their own account (paying the linear `add_key_cost` for each, spread across many blocks/receipts) and then submit a single `DeleteAccount` action. Runtime execution of that single receipt will:
- Iterate over the full `ACCESS_KEY` trie prefix for the account (unbounded I/O/CPU).
- Issue one `state_update.remove()` per key (unbounded state-update/trie work).
- Only be charged the fixed `delete_account_cost` execution fee, i.e., essentially free/underpriced execution proportional to the actual work performed.

Because this all happens inside the processing of a single receipt (subject to the chunk's compute/gas limit check, which is only evaluated *between* receipts, not mid-iteration — see the receipt-processing loop in `runtime/runtime/src/lib.rs:2406-2421` and `2519-2521`), an attacker can size the number of access keys so that a single `DeleteAccount` receipt consumes far more wall-clock/compute resources than its charged gas would suggest, without the runtime being able to interrupt it mid-flight. This risks chunk-application slow-downs (nodes falling behind, degraded liveness) and constitutes free/underpriced execution — the same "unbounded resource use for an under-priced unprivileged operation" impact class as the reported external bug, though bounded in practice by `Account::MAX_ACCOUNT_DELETION_STORAGE_USAGE`, which caps total account storage usage (and hence indirectly caps the number of access keys) before `DeleteAccount` is even allowed to proceed (`runtime/runtime/src/actions.rs:333-338`).

### Likelihood Explanation
Reachable by any account: creating many `AddKey` receipts followed by a `DeleteAccount` receipt requires no special privilege, only ordinary transaction gas payments. However, the likelihood of *exceeding* the storage-staking economics is reduced by two existing mitigations: (1) `MAX_ACCOUNT_DELETION_STORAGE_USAGE` bounds the account's total storage usage (and hence access-key count) before deletion is permitted, and (2) each `AddKey` costs real NEAR in storage staking and gas, making a large-scale attack economically non-trivial. The unmetered-compute gap is real and confirmed in code, but whether the resulting single-receipt work at the storage-usage cap is large enough to cause a practically significant chunk-processing stall was not verified against the exact value of `MAX_ACCOUNT_DELETION_STORAGE_USAGE` nor benchmarked; this remains an open question requiring further investigation (e.g., via `runtime/runtime-params-estimator`).

### Recommendation
- Extend `RemoveAccountResult` to also report the count/total-bytes of regular access keys removed, mirroring what's already done for gas-key nonces.
- In `action_delete_account`, add compute accounting (via `storage_removes_compute`) for the regular access-key removals in addition to the gas-key-nonce removals, so the compute cost charged reflects the true amount of trie work performed.
- Alternatively/additionally, ensure the account-deletion storage-usage cap (`MAX_ACCOUNT_DELETION_STORAGE_USAGE`) is verified to bound worst-case compute for this path within safe limits, and add a params-estimator benchmark for "delete account with N regular access keys" to validate the fixed `delete_account_cost` remains representative.

### Proof of Concept
1. Attacker account `A` submits many transactions with `AddKeyAction { public_key: pk_i, access_key: AccessKey::full_access() }` for i = 1..N (paying `add_key_cost` per key, capped by `MAX_ACCOUNT_DELETION_STORAGE_USAGE`).
2. Attacker submits a single `DeleteAccountAction { beneficiary_id: A }` on account `A`.
3. During execution, `action_delete_account` (`runtime/runtime/src/actions.rs:299`) calls `remove_account` (`core/store/src/utils/mod.rs:487`), which iterates all N access-key trie entries and issues N `state_update.remove()` calls.
4. `result.compute_usage` is only incremented for gas-key nonces (none exist here), so the transaction sender is charged just the constant `delete_account_cost` (~147 Ggas) regardless of N, while the runtime performs O(N) trie iteration and removal work in a single un-interruptible receipt execution. [2](#0-1) [4](#0-3)

### Citations

**File:** core/store/src/utils/mod.rs (L481-484)
```rust
pub struct RemoveAccountResult {
    pub gas_key_nonce_count: usize,
    pub gas_key_nonce_total_key_bytes: usize, // used to calculate compute cost
}
```

**File:** core/store/src/utils/mod.rs (L486-557)
```rust
/// Removes account, code and all access keys and gas keys associated to it.
pub fn remove_account(
    state_update: &mut TrieUpdate,
    account_id: &AccountId,
) -> Result<RemoveAccountResult, StorageError> {
    state_update.remove(TrieKey::Account { account_id: account_id.clone() });
    state_update.remove(TrieKey::ContractCode { account_id: account_id.clone() });

    let mut gas_key_nonce_count: usize = 0;
    let mut gas_key_nonce_total_key_bytes: usize = 0;

    // Removing access keys and gas key nonces
    let lock = state_update.trie().lock_for_iter();
    let mut keys_to_remove: Vec<TrieKey> = Vec::new();
    for raw_key in state_update
        .locked_iter(&trie_key_parsers::get_raw_prefix_for_access_keys(account_id), &lock)?
    {
        let raw_key = raw_key?;
        let key_handle = trie_key_parsers::parse_key_handle_from_access_key_key(
            &raw_key, account_id,
        )
        .map_err(|_e| {
            StorageError::StorageInconsistentState(
                "Can't parse key handle from raw key for AccessKey".to_string(),
            )
        })?;
        let nonce_index =
            trie_key_parsers::parse_nonce_index_from_gas_key_key(&raw_key, account_id, &key_handle)
                .map_err(|_e| {
                    StorageError::StorageInconsistentState(
                        "Can't parse nonce index from raw key for AccessKey".to_string(),
                    )
                })?;
        if let Some(index) = nonce_index {
            gas_key_nonce_count += 1;
            gas_key_nonce_total_key_bytes += raw_key.len();
            keys_to_remove.push(TrieKey::gas_key_nonce(
                account_id.clone(),
                key_handle.clone(),
                index,
            ));
        } else {
            keys_to_remove.push(TrieKey::access_key(account_id.clone(), key_handle.clone()));
        }
    }
    drop(lock);

    for trie_key in keys_to_remove {
        state_update.remove(trie_key);
    }

    // Removing contract data
    let lock = state_update.trie().lock_for_iter();
    let data_keys = state_update
        .locked_iter(&trie_key_parsers::get_raw_prefix_for_contract_data(account_id, &[]), &lock)?
        .map(|raw_key| {
            trie_key_parsers::parse_data_key_from_contract_data_key(&raw_key?, account_id)
                .map_err(|_e| {
                    StorageError::StorageInconsistentState(
                        "Can't parse data key from raw key for ContractData".to_string(),
                    )
                })
                .map(Vec::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    drop(lock);

    for key in data_keys {
        state_update.remove(TrieKey::ContractData { account_id: account_id.clone(), key });
    }
    Ok(RemoveAccountResult { gas_key_nonce_count, gas_key_nonce_total_key_bytes })
}
```

**File:** runtime/runtime/src/actions.rs (L356-371)
```rust
    let remove_result = remove_account(state_update, account_id)?;
    result.tokens_burnt =
        result.tokens_burnt.checked_add(gas_key_balance_to_burn).ok_or_else(|| {
            StorageError::StorageInconsistentState("tokens_burnt overflow".to_string())
        })?;
    if remove_result.gas_key_nonce_count > 0 {
        let compute = storage_removes_compute(
            &config.wasm_config.ext_costs,
            remove_result.gas_key_nonce_count,
            remove_result.gas_key_nonce_total_key_bytes,
            AccessKey::NONCE_VALUE_LEN * remove_result.gas_key_nonce_count,
        );
        result.compute_usage = safe_add_compute(result.compute_usage, compute).map_err(|_| {
            StorageError::StorageInconsistentState("compute_usage overflow".to_string())
        })?;
    }
```

**File:** docs/RuntimeSpec/Fees/Fees.md (L73-76)
```markdown
- [DeleteAccount](/RuntimeSpec/Actions.md#deleteaccountaction) uses
  - the base fee [`delete_account_cost`](/GenesisConfig/RuntimeFeeConfig/ActionCreationConfig.md#delete_account_cost)
  - action receipt creation fee for creating Transfer to send remaining funds to `beneficiary_id`
  - full transfer fee described in the corresponding item
```
