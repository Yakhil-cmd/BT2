### Title
Storage writes in `deploy_deterministic_account` are committed to the trie before the storage-stake balance check can fail, allowing free/unbacked state growth - (File: `runtime/runtime/src/deterministic_account_id.rs`)

### Summary
`action_deterministic_state_init` calls `deploy_deterministic_account`, which unconditionally performs `state_update.set(...)` writes for the contract code (`use_global_contract`) and every `ContractData` key/value pair in `state_init.data()`, **before** the deposit is checked against `check_storage_stake`. When the check fails with `LackBalanceForState`, the function returns `Ok(())` with `result.result` set to an error, but the trie writes already staged in `state_update` are not undone.

### Finding Description
The relevant control flow is: [1](#0-0) 

`deploy_deterministic_account` writes contract code and all `ContractData` entries directly into the shared `state_update: &mut TrieUpdate` unconditionally: [2](#0-1) 

Only *afterwards* does the function check `check_storage_stake` against `action.deposit`: [3](#0-2) 

If `missing_amount > action.deposit`, the function sets `result.result = Err(ActionErrorKind::LackBalanceForState { .. })` and returns `Ok(())` without pushing any refund receipt and without reverting the `state_update.set` calls performed moments earlier in `deploy_deterministic_account`. This is a clear ordering inversion relative to the established pattern elsewhere in the runtime (checks-before-writes), and there is no per-action checkpoint/rollback API on `TrieUpdate` invoked here to undo the staged writes when the action later fails. The `account` object itself (holding `storage_usage`) may or may not be committed by the caller depending on `result.result` being `Ok`, but the raw `ContractData`/global-contract-code writes already staged into `state_update` are independent of that account-commit gate — they were pushed straight into the pending trie changes, which get finalized when the chunk's `state_update` is committed at the end of receipt processing, regardless of the individual action's failure.

An attacker can trivially trigger this by submitting a `DeterministicStateInitAction` with `action.deposit = 0` and a large `state_init.data()` payload for a fresh (`nonexist`) account. The account is created in-memory with zero balance, all data is unconditionally written to the trie, and only then does `check_storage_stake` fail — by which point the writes are already staged.

### Impact Explanation
This is a storage-metering/state-bloat bypass: an attacker can insert arbitrarily large `ContractData` records into the trie while paying zero deposit and while the action is reported as failed (`LackBalanceForState`), with no refund receipt needed (nothing to refund) and no debit charged. Repeated at scale, this allows unbounded, unpriced growth of the state trie, which is the "unbounded state bloat / free storage growth" impact class explicitly targeted by NEAR's storage staking invariant (all state must be backed by locked balance).

### Likelihood Explanation
The precondition is trivial and fully attacker-controlled: an ordinary account holder submits a `DeterministicStateInitAction` receipt/transaction with a deliberately insufficient deposit and a large `state_init.data()` map. No special privileges, races, or validator cooperation are required — this is reachable directly from a normal transaction through public RPC. The bug is deterministic and repeatable on every call.

### Recommendation
Reorder `action_deterministic_state_init`/`deploy_deterministic_account` so that the storage-stake sufficiency check happens **before** any `state_update.set` calls are issued (compute the prospective `storage_usage` cost of `state_init.code()`/`state_init.data()` first, run `check_storage_stake` against the projected usage, and only perform the trie writes once the check passes). Alternatively, if writes must happen first for architectural reasons, ensure the enclosing receipt-processing logic in `runtime/runtime/src/lib.rs` discards/rolls back all `TrieUpdate` changes associated with a failed action (not just the `Account` row) before the update is committed to the trie.

### Proof of Concept
Integration test plan (in `runtime/runtime/src/tests` or an integration test crate):
1. Construct a fresh account (`nonexist` state) and submit a `DeterministicStateInitAction` with `deposit = 0` and `state_init.data()` containing e.g. 100 KB across several keys, and `state_init.code()` pointing at a valid global contract.
2. Apply the receipt through the runtime.
3. Assert the receipt/action result is `Err(ActionErrorKind::LackBalanceForState { .. })`.
4. Query the resulting state root/trie for `TrieKey::ContractData { account_id, key }` for the keys submitted, and for the global-contract-code association on the account.
5. Expected (secure) behavior: none of these keys exist in the trie after the failed action. Actual (vulnerable) behavior: the keys are present, demonstrating unpriced, persisted state growth from a failed, zero-deposit action.

### Citations

**File:** runtime/runtime/src/deterministic_account_id.rs (L38-51)
```rust
    if account.contract().is_none() {
        // `uninit` -> `active` account state transition
        deploy_deterministic_account(
            state_update,
            account,
            account_id,
            &action.state_init,
            result,
            storage_usage_config,
        )?;
    }
    if result.result.is_err() {
        return Ok(());
    }
```

**File:** runtime/runtime/src/deterministic_account_id.rs (L55-81)
```rust
    let deposit_refund = match check_storage_stake(account, account.amount(), &apply_state.config) {
        Ok(_) => {
            // no additional storage needed, refunding all
            action.deposit
        }
        Err(StorageStakingError::LackBalanceForStorageStaking(missing_amount)) => {
            if missing_amount <= action.deposit {
                // use exactly as much as needed and refund the rest
                let new_balance = safe_add_balance(account.amount(), missing_amount)?;
                account.set_amount(new_balance);
                action
                    .deposit
                    .checked_sub(missing_amount)
                    .expect("just checked missing_amount <= action.deposit")
            } else {
                result.result = Err(ActionErrorKind::LackBalanceForState {
                    account_id: account_id.clone(),
                    amount: missing_amount,
                }
                .into());
                return Ok(());
            }
        }
        Err(StorageStakingError::StorageError(err)) => {
            return Err(RuntimeError::StorageError(StorageError::StorageInconsistentState(err)));
        }
    };
```

**File:** runtime/runtime/src/deterministic_account_id.rs (L131-148)
```rust
    // Step 2: insert provided key-value pairs
    let mut required_storage_usage = account.storage_usage();
    for (key, value) in state_init.data() {
        let trie_key = TrieKey::ContractData { account_id: account_id.clone(), key: key.to_vec() };

        let value_bytes = value.len() as u64;
        let key_bytes = key.len() as u64;
        let extra_per_record_bytes = storage_usage_config.num_extra_bytes_record;

        let new_bytes = value_bytes
            .checked_add(key_bytes)
            .and_then(|acc| acc.checked_add(extra_per_record_bytes))
            .ok_or(IntegerOverflowError {})?;
        state_update.set(trie_key, value.clone());
        required_storage_usage =
            required_storage_usage.checked_add(new_bytes).ok_or(IntegerOverflowError {})?;
    }
    account.set_storage_usage(required_storage_usage);
```
