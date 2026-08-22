### Title
Stale `YieldIdToDataId`/`DataIdToYieldId` and `PromiseYieldStatus`/`PromiseYieldReceipt` trie entries are not purged on account deletion, permanently blocking custom-yield-id reuse and leaking unaccounted trie storage - (File: `core/store/src/utils/mod.rs`)

### Summary
`remove_account` (invoked from `action_delete_account`) removes an account's `Account`, `ContractCode`, access keys, gas-key nonces, and contract data, but never removes the account's `PromiseYieldReceipt`, `PromiseYieldStatus`, `YieldIdToDataId`, or `DataIdToYieldId` trie entries. This is structurally the same bug class as the reported `unregisterOperatorVault` issue: an "unregister"/removal path clears the primary registry but not the sibling extension mapping that gates re-creation, leaving a stale flag that blocks future creation and returns stale data forever.

### Finding Description
`promise_yield_create_with_id` writes bidirectional mappings keyed by `receiver_id` (the account) via `set_yield_id_mapping`, and gates duplicate creation with `has_yield_id_mapping`: [1](#0-0) 

The duplicate check reads directly from the trie for the receiver account, with no account-existence check: [2](#0-1) 

Cleanup of these mappings, along with `PromiseYieldStatus` and `PromiseYieldReceipt`, only happens along the "happy path" when a `PromiseResume` receipt for the corresponding `data_id` is delivered to the (still existing) account: [3](#0-2) 

However, `action_delete_account` — reachable directly from a `DeleteAccount` transaction action — calls `remove_account`, which enumerates and deletes `Account`, `ContractCode`, access keys/gas-key nonces, and contract data, but has no logic at all for `PromiseYieldReceipt`, `PromiseYieldStatus`, `YieldIdToDataId`, or `DataIdToYieldId` trie keys: [4](#0-3) [5](#0-4) 

Because `TrieKey::PromiseYieldReceipt`, `TrieKey::PromiseYieldStatus`, `TrieKey::YieldIdToDataId`, and `TrieKey::DataIdToYieldId` are all namespaced under `receiver_id` (the account id) rather than tied to `Account` existence, deleting the account leaves these entries dangling in the trie: [6](#0-5) [7](#0-6) 

This is directly analogous to the Sherlock finding: `_registerOperatorImpl`/`createVault` populates `_autoDeployedVault[operator]`, and `unregisterOperatorVault` deletes the vault from the core registry but never clears `_autoDeployedVault`, so `getAutoDeployedVault` forever returns a stale, unregistered vault and the operator can never get a fresh auto-deployed vault. Here, `promise_yield_create_with_id` populates `YieldIdToDataId`/`DataIdToYieldId` for an account, and `action_delete_account`/`remove_account` deletes the account's core state but never clears those extension mappings, so `has_yield_id_mapping` forever returns `true` for that (account_id, yield_id) pair and `get_data_id_for_yield_id`/`get_yield_id_for_data_id` forever return stale data.

### Impact Explanation
- **Permanent functional blocking**: If an account id can be reused after deletion (NEAR account ids can be re-created after `DeleteAccount`), any future contract deployed to that account id can never successfully call `promise_yield_create_with_id` with a `yield_id` that was ever used pre-deletion — `create_promise_yield_receipt_with_id` will forever return `None`/`u64::MAX` for that id, since `has_yield_id_mapping` checks raw trie state, not liveness of the associated receipt or account. This is a permanent state-divergence-from-intended-behavior bug reachable purely from account-owner-issued transactions (`FunctionCall` triggering `promise_yield_create_with_id` + a later `DeleteAccount`), matching the report's "operator can never create a new vault" impact.
- **Unaccounted, permanently leaked trie storage**: The orphaned `PromiseYieldReceipt`, `PromiseYieldStatus`, `YieldIdToDataId`, and `DataIdToYieldId` entries are never charged to the deleted account's storage usage accounting (which is computed purely from `Account.storage_usage()`/contract storage in `action_delete_account`), and once the account is gone there is no owner paying rent/storage-staking for this data going forward — it persists in state indefinitely with no way to remove it. Repeating create-yield-with-id + delete-account cycles from many distinct accounts allows continual, permanent state growth that bypasses per-account storage-staking accounting.
- **Stale reads**: If somehow the corresponding `PromiseResume` receipt is delivered later to the deleted-then-recreated account_id with the same `data_id`, timeout/duplicate-resume logic based on `get_promise_yield_status` could behave incorrectly against the freshly recreated account's unrelated state, since the check does not verify epoch/account identity beyond account_id string equality.

### Likelihood Explanation
Reaching this requires only ordinary, unprivileged actions: a contract account calling `promise_yield_create_with_id` (a stable, documented host function) followed by that same account issuing a `DeleteAccount` action before the yield resolves. Both are default capabilities of any account owner; no validator/node-privilege or malicious-peer behavior is needed. Account re-creation under the same id after deletion is a standard, supported NEAR feature. This makes the bug straightforwardly and repeatably triggerable.

### Recommendation
Extend `remove_account` in `core/store/src/utils/mod.rs` to also iterate and delete any `TrieKey::PromiseYieldReceipt`, `TrieKey::PromiseYieldStatus`, `TrieKey::YieldIdToDataId`, and `TrieKey::DataIdToYieldId` entries scoped to the account being deleted (mirroring how access keys and gas-key nonces are enumerated and removed), and include their storage/compute cost in `RemoveAccountResult` so `action_delete_account` in `runtime/runtime/src/actions.rs` correctly accounts for the removal. Alternatively/additionally, reject `DeleteAccount` while the account has outstanding `PromiseYieldStatus`/`YieldIdToDataId` entries, similar to how large-state deletion is currently rejected.

### Proof of Concept
Conceptual reproduction (no PoC harness run; based on code paths above):
1. Deploy a contract to account `alice.near`. Have it call `promise_yield_create_with_id` with a fixed `yield_id = X`. This calls `create_promise_yield_receipt_with_id`, which calls `set_yield_id_mapping(state_update, "alice.near", X, data_id)` and `set_promise_yield_status(..., Yielded)`. [1](#0-0) 
2. Before the corresponding `PromiseResume` is delivered (i.e., before `resume`/timeout fires), submit a `DeleteAccount` transaction/action for `alice.near`. `action_delete_account` calls `remove_account`, which deletes `Account`, `ContractCode`, access keys, and contract data — but not `YieldIdToDataId`/`DataIdToYieldId`/`PromiseYieldStatus`/`PromiseYieldReceipt`. [4](#0-3) 
3. Re-create account `alice.near` (standard `CreateAccount` action) and deploy a new (or the same) contract. Have it call `promise_yield_create_with_id` again with the same `yield_id = X`. `has_yield_id_mapping(trie, "alice.near", X)` will read the still-present stale `YieldIdToDataId` entry from step 1 and return `true`, causing `create_promise_yield_receipt_with_id` to return `None` (host function returns `u64::MAX`) forever for that yield_id — even though the entity is a fresh account with no memory of the original yield. [2](#0-1) [1](#0-0)

### Citations

**File:** runtime/runtime/src/ext.rs (L364-393)
```rust
    fn create_promise_yield_receipt_with_id(
        &mut self,
        receiver_id: AccountId,
        user_yield_id: YieldId,
    ) -> Result<Option<(ReceiptIndex, CryptoHash)>, VMLogicError> {
        // Check for duplicate yield_id in trie. TrieUpdate also reflects writes from earlier
        // calls within the same function call, so this also catches in-transaction duplicates.
        if has_yield_id_mapping(self.trie_update, &receiver_id, user_yield_id)
            .map_err(wrap_storage_error)?
        {
            return Ok(None);
        }

        let input_data_id = self.generate_data_id();

        // Store bidirectional yield_id <-> data_id mappings
        set_yield_id_mapping(&mut self.trie_update, &receiver_id, user_yield_id, input_data_id);

        let receipt_index =
            self.receipt_manager.create_promise_yield_receipt(input_data_id, receiver_id.clone());

        set_promise_yield_status(
            &mut self.trie_update,
            &receiver_id,
            input_data_id,
            PromiseYieldStatus::Yielded,
        );

        Ok(Some((receipt_index, input_data_id)))
    }
```

**File:** core/store/src/utils/mod.rs (L182-211)
```rust
pub fn set_promise_yield_receipt(state_update: &mut TrieUpdate, receipt: &Receipt) {
    match receipt.versioned_receipt() {
        VersionedReceiptEnum::PromiseYield(action_receipt) => {
            assert!(action_receipt.input_data_ids().len() == 1);
            let key = TrieKey::PromiseYieldReceipt {
                receiver_id: receipt.receiver_id().clone(),
                data_id: action_receipt.input_data_ids()[0],
            };
            set(state_update, key, receipt);
        }
        _ => unreachable!("Expected PromiseYield receipt"),
    }
}

pub fn remove_promise_yield_receipt(
    state_update: &mut TrieUpdate,
    receiver_id: &AccountId,
    data_id: CryptoHash,
) {
    state_update.remove(TrieKey::PromiseYieldReceipt { receiver_id: receiver_id.clone(), data_id });
}

pub fn get_promise_yield_receipt(
    trie: &dyn TrieAccess,
    receiver_id: &AccountId,
    data_id: CryptoHash,
) -> Result<Option<Receipt>, StorageError> {
    get(trie, &TrieKey::PromiseYieldReceipt { receiver_id: receiver_id.clone(), data_id })
}

```

**File:** core/store/src/utils/mod.rs (L242-316)
```rust
pub fn set_promise_yield_status(
    state_update: &mut TrieUpdate,
    receiver_id: &AccountId,
    data_id: CryptoHash,
    status: PromiseYieldStatus,
) {
    set(
        state_update,
        TrieKey::PromiseYieldStatus { receiver_id: receiver_id.clone(), data_id },
        &status,
    );
}

pub fn remove_promise_yield_status(
    state_update: &mut TrieUpdate,
    receiver_id: &AccountId,
    data_id: CryptoHash,
) {
    state_update.remove(TrieKey::PromiseYieldStatus { receiver_id: receiver_id.clone(), data_id });
}

pub fn set_yield_id_mapping(
    state_update: &mut TrieUpdate,
    receiver_id: &AccountId,
    yield_id: YieldId,
    data_id: CryptoHash,
) {
    set(
        state_update,
        TrieKey::YieldIdToDataId { receiver_id: receiver_id.clone(), yield_id },
        &data_id,
    );
    set(
        state_update,
        TrieKey::DataIdToYieldId { receiver_id: receiver_id.clone(), data_id },
        &yield_id,
    );
}

pub fn get_data_id_for_yield_id(
    trie: &dyn TrieAccess,
    receiver_id: &AccountId,
    yield_id: YieldId,
) -> Result<Option<CryptoHash>, StorageError> {
    get(trie, &TrieKey::YieldIdToDataId { receiver_id: receiver_id.clone(), yield_id })
}

pub fn get_yield_id_for_data_id(
    trie: &dyn TrieAccess,
    receiver_id: &AccountId,
    data_id: CryptoHash,
) -> Result<Option<YieldId>, StorageError> {
    get(trie, &TrieKey::DataIdToYieldId { receiver_id: receiver_id.clone(), data_id })
}

pub fn has_yield_id_mapping(
    trie: &dyn TrieAccess,
    receiver_id: &AccountId,
    yield_id: YieldId,
) -> Result<bool, StorageError> {
    trie.contains_key(
        &TrieKey::YieldIdToDataId { receiver_id: receiver_id.clone(), yield_id },
        AccessOptions::DEFAULT,
    )
}

pub fn remove_yield_id_mappings(
    state_update: &mut TrieUpdate,
    receiver_id: &AccountId,
    yield_id: YieldId,
    data_id: CryptoHash,
) {
    state_update.remove(TrieKey::YieldIdToDataId { receiver_id: receiver_id.clone(), yield_id });
    state_update.remove(TrieKey::DataIdToYieldId { receiver_id: receiver_id.clone(), data_id });
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

**File:** runtime/runtime/src/lib.rs (L1421-1458)
```rust
            VersionedReceiptEnum::PromiseResume(data_receipt) => {
                if data_receipt.data.is_none() {
                    // This is a timeout resume. Check the status to see if the receipt has been resumed.
                    let status =
                        get_promise_yield_status(state_update, account_id, data_receipt.data_id)?;
                    if status == Some(PromiseYieldStatus::ResumeInitiated) {
                        // A non-timeout resume receipt has been sent, cancel the timeout.
                        return Ok(None);
                    }
                }

                // Received a new PromiseResume receipt delivering input data for a PromiseYield.
                // It is guaranteed that the PromiseYield has exactly one input data dependency
                // and that it arrives first, so we can simply find and execute it.
                if let Some(yield_receipt) =
                    get_promise_yield_receipt(state_update, account_id, data_receipt.data_id)?
                {
                    // Remove the receipt from the state
                    remove_promise_yield_receipt(state_update, account_id, data_receipt.data_id);

                    // Clear the PromiseYield status
                    remove_promise_yield_status(state_update, account_id, data_receipt.data_id);

                    // Clean up yield_id <-> data_id mappings if this was created by yield_create_with_id
                    if ProtocolFeature::YieldWithId.enabled(apply_state.current_protocol_version) {
                        if let Some(yield_id) = get_yield_id_for_data_id(
                            state_update,
                            account_id,
                            data_receipt.data_id,
                        )? {
                            remove_yield_id_mappings(
                                state_update,
                                account_id,
                                yield_id,
                                data_receipt.data_id,
                            );
                        }
                    }
```

**File:** runtime/runtime/src/actions.rs (L299-375)
```rust
pub(crate) fn action_delete_account(
    state_update: &mut TrieUpdate,
    account: &mut Option<Account>,
    actor_id: &mut AccountId,
    receipt: &Receipt,
    result: &mut ActionResult,
    account_id: &AccountId,
    delete_account: &DeleteAccountAction,
    config: &RuntimeConfig,
    current_protocol_version: ProtocolVersion,
) -> Result<(), StorageError> {
    let account_ref = account.as_ref().unwrap();
    let account_storage_usage = if ProtocolFeature::FixDeleteAccountGlobalContractStorageUsage
        .enabled(current_protocol_version)
    {
        let contract_storage = get_contract_storage_usage(state_update, account_id, account_ref)?;
        account_ref.storage_usage().saturating_sub(contract_storage)
    } else {
        // Legacy behavior: only subtracts local contract code, misses the
        // global contract identifier overhead.
        let account_storage_usage = account_ref.storage_usage();
        let code_len = get_code_len_or_default(
            state_update,
            account_id.clone(),
            account_ref.local_contract_hash().unwrap_or_default(),
        )?;
        debug_assert!(
            code_len == 0 || account_storage_usage > code_len,
            "account storage usage should be larger than code size. storage usage: {}, code size: {}",
            account_storage_usage,
            code_len
        );
        account_storage_usage.saturating_sub(code_len)
    };
    if account_storage_usage > Account::MAX_ACCOUNT_DELETION_STORAGE_USAGE {
        result.result =
            Err(ActionErrorKind::DeleteAccountWithLargeState { account_id: account_id.clone() }
                .into());
        return Ok(());
    }
    let gas_key_balance_to_burn = compute_gas_key_balance_sum(state_update, account_id)?;
    if gas_key_balance_to_burn > GasKeyInfo::MAX_BALANCE_TO_BURN {
        result.result = Err(ActionErrorKind::GasKeyBalanceTooHigh {
            account_id: account_id.clone(),
            public_key: None,
            balance: gas_key_balance_to_burn,
        }
        .into());
        return Ok(());
    }
    // We use current amount as a pay out to beneficiary.
    let account_balance = account_ref.amount();
    if account_balance > Balance::ZERO {
        result
            .new_receipts
            .push(Receipt::new_balance_refund(&delete_account.beneficiary_id, account_balance));
    }
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
    *actor_id = receipt.predecessor_id().clone();
    *account = None;
    Ok(())
}
```
