### Title
Stale cross-shard receipt-matching state (`PostponedReceipt`/`PostponedReceiptId`/`PendingDataCount`/`ReceivedData`) is not purged on `DeleteAccountAction`, allowing a re-created `AccountId` to be hijacked by a prior owner's in-flight receipt - (File: `core/store/src/utils/mod.rs`, `runtime/runtime/src/actions.rs`)

### Summary
This is the nearcore protocol-level analog of the reported "stale mapping after re-registration" bug class. In the Initia report, `register_domain` cleared the `name_to_token` mapping but left `name_to_addr`/`addr_to_name` pointing at the old owner, so a re-registered (re-owned) domain could still resolve to the previous owner. In nearcore, `AccountId`s behave like the reusable "domain name": an account can be deleted (`DeleteAccountAction`) and later re-created (`CreateAccountAction`) by a *different* controller. `remove_account`, the routine invoked on account deletion, only clears the account record, contract code, access/gas keys and contract data — it never clears the receipt-matching bookkeeping (`TrieKey::PostponedReceipt`, `TrieKey::PostponedReceiptId`, `TrieKey::PendingDataCount`, `TrieKey::ReceivedData`, and the analogous `PromiseYieldReceipt`/`PromiseYieldStatus` keys) that is indexed purely by `account_id`. If a pending cross-contract callback for that `account_id` is still outstanding at the moment of deletion, it survives in the trie and will later be matched and executed against whichever new account now occupies that same `AccountId`.

### Finding Description
`remove_account` (invoked from `action_delete_account`) explicitly removes only: [1](#0-0) 
access keys and gas-key nonces: [2](#0-1) 
and contract data: [3](#0-2) 

It never touches the account's receipt-matching keys (`PostponedReceipt`, `PostponedReceiptId`, `PendingDataCount`, `ReceivedData`), which are documented as being keyed purely by `receiver_id`/`account_id` and `receipt_id`/`data_id`: [4](#0-3) 

`action_delete_account` calls `remove_account` and then simply drops the in-memory `Account`, with no check for outstanding postponed receipts tied to that account: [5](#0-4) 

Meanwhile, when a `DataReceipt` eventually arrives for a given `receiver_id`/`data_id`, `process_receipt` looks up `TrieKey::PostponedReceiptId` purely by `account_id`+`data_id` — with no verification that the account still refers to the same logical owner/generation that created the postponed entry — decrements `PendingDataCount`, and once it reaches zero, fetches and executes the stored `PostponedReceipt` via `apply_action_receipt`: [6](#0-5) 

Because `AccountId`s in NEAR are not permanently reserved after deletion (a deleted sub-account name, or a deleted implicit/top-level account, can be freshly re-created by an unrelated party — confirmed by the fact that `AccountAlreadyExists` is only raised when the account currently exists, not when it once existed and was deleted): [7](#0-6) 

...a malicious or careless prior owner of an `account_id` can leave a pending cross-contract promise-then callback (a `PostponedReceipt` whose actions were authored under the old contract's logic/state) in flight, delete the account, and have that stale receipt fire later against the new occupant's account — directly mirroring the reported "old mapping still points to previous owner, bypassing the fresh-registration guarantee" defect.

### Impact Explanation
This breaks the same protocol invariant the report describes: state indexed by a reusable name/identifier is not invalidated when ownership of that identifier changes hands. Concretely, once account `X` is deleted and a new, unrelated account named `X` is created, the runtime can still deliver a `DataReceipt` that resolves an old `PostponedReceipt` keyed to `X`, and `apply_action_receipt` will execute that receipt's actions against the *new* account `X`'s state — potentially performing `Transfer`, `AddKey`, `FunctionCall`, or `DeleteAccount` actions that were queued by the old owner's contract logic but land on the new owner's balance/keys/contract. This is an unauthorized-state/balance-change vector consistent with the required "concrete unauthorized state or balance change" impact class, without needing any validator or peer collusion — a single account holder can construct this sequence with ordinary transactions/receipts.

### Likelihood Explanation
Reaching this state requires: (1) a contract/account that issues a promise with a `.then()` continuation targeting itself (or another account) and is awaiting a `DataReceipt` from a cross-shard/cross-contract call, (2) the same account being deleted via `DeleteAccountAction` before that data arrives — which is not blocked by any check in `action_delete_account` for outstanding postponed receipts, and (3) the same `AccountId` being re-created before the delayed `DataReceipt` is delivered. Step (3) is entirely plausible for account names that go through re-registration (sub-account under a shared parent, or a released top-level name), and cross-shard receipt delivery latency (multiple blocks under congestion) provides the timing window. This is a multi-step but fully unprivileged, protocol-reachable path — comparable in likelihood/severity framing to the Medium-rated original finding, which itself required "several things to happen in the right order."

### Recommendation
When executing `DeleteAccountAction`, either (a) reject the deletion if the account still has any outstanding `PostponedReceipt`/`PendingDataCount`/`PostponedReceiptId`/`PromiseYieldReceipt` entries (analogous to the existing `DeleteAccountStaking` check), or (b) have `remove_account` (or a dedicated cleanup routine called from `action_delete_account`) enumerate and purge all such receipt-matching trie keys prefixed by the deleted `account_id`, burning/refunding any associated deposits, before the account is considered fully removed. This mirrors the report's recommended fix of clearing all stale identity-keyed mappings at the point of ownership change rather than relying on downstream consumers to re-validate freshness.

### Proof of Concept
Conceptual reproduction (analogous to the report's PoC pattern):
1. Account `child.alice.near` deploys a contract and issues `promise::create(other.near, "foo").then(child.alice.near::callback)`. This produces an `ActionReceipt` with `receiver_id = child.alice.near` and a non-empty `input_data_ids`, which gets stored as `PostponedReceipt`/`PendingDataCount`/`PostponedReceiptId` (see `process_action_receipt`, `runtime/runtime/src/lib.rs:1514-1579`) while awaiting the `DataReceipt` from `other.near`.
2. Before that `DataReceipt` is delivered (e.g., across shards over several blocks), the owner of `child.alice.near` submits `DeleteAccountAction` (beneficiary = self/alice). `remove_account` clears the `Account`, keys, code, and contract data, but leaves the `PostponedReceipt`/`PendingDataCount`/`PostponedReceiptId` trie entries for `child.alice.near` untouched (`core/store/src/utils/mod.rs:487-556`).
3. `alice.near` (or anyone permitted) re-creates `child.alice.near` as a fresh account — allowed since the account no longer exists (`AccountAlreadyExists` only triggers on a currently-existing account, per `integration-tests/src/tests/standard_cases/mod.rs:852-861`).
4. The delayed `DataReceipt` from `other.near` finally arrives with `receiver_id = child.alice.near`. `process_receipt` matches it against the still-present `PostponedReceiptId`, decrements `PendingDataCount` to zero, fetches the stale `PostponedReceipt`, and calls `apply_action_receipt`, executing the old callback's actions against the newly created `child.alice.near` account (`runtime/runtime/src/lib.rs:1307-1376`).

I was not able to execute this against a live nearcore test harness in this session (no filesystem/terminal access), so the exact action set that would produce measurable fund loss (e.g., whether the callback batch included a `Transfer` or `AddKey` action) is asserted from the code paths above rather than empirically demonstrated; a background Devin session with repo/test access would be needed to write and run a concrete `runtime/runtime/src/tests/apply.rs`-style integration test exercising steps 1–4 to confirm the exact executed-action outcome.

### Citations

**File:** core/store/src/utils/mod.rs (L486-492)
```rust
/// Removes account, code and all access keys and gas keys associated to it.
pub fn remove_account(
    state_update: &mut TrieUpdate,
    account_id: &AccountId,
) -> Result<RemoveAccountResult, StorageError> {
    state_update.remove(TrieKey::Account { account_id: account_id.clone() });
    state_update.remove(TrieKey::ContractCode { account_id: account_id.clone() });
```

**File:** core/store/src/utils/mod.rs (L497-535)
```rust
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
```

**File:** core/store/src/utils/mod.rs (L537-556)
```rust
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
```

**File:** core/primitives/src/trie_key.rs (L203-219)
```rust
    /// purposes to avoid deserializing the entire receipt.
    PostponedReceiptId {
        receiver_id: AccountId,
        data_id: CryptoHash,
    } = col::POSTPONED_RECEIPT_ID,
    /// Used to store the number of still missing input data `u32` for a given receiver's
    /// `AccountId` and a given `receipt_id` of the receipt.
    PendingDataCount {
        receiver_id: AccountId,
        receipt_id: CryptoHash,
    } = col::PENDING_DATA_COUNT,
    /// Used to store the postponed receipt `primitives::receipt::Receipt` for a given receiver's
    /// `AccountId` and a given `receipt_id` of the receipt.
    PostponedReceipt {
        receiver_id: AccountId,
        receipt_id: CryptoHash,
    } = col::POSTPONED_RECEIPT,
```

**File:** runtime/runtime/src/actions.rs (L299-356)
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
```

**File:** runtime/runtime/src/lib.rs (L1307-1376)
```rust
            VersionedReceiptEnum::Data(data_receipt) => {
                // Received a new data receipt.
                // Saving the data into the state keyed by the data_id.
                set_received_data(
                    state_update,
                    account_id.clone(),
                    data_receipt.data_id,
                    &ReceivedData { data: data_receipt.data.clone() },
                );
                // Check if there is already a receipt that was postponed and was awaiting for the
                // given data_id.
                // If we don't have a postponed receipt yet, we don't need to do anything for now.
                if let Some(receipt_id) = get(
                    state_update,
                    &TrieKey::PostponedReceiptId {
                        receiver_id: account_id.clone(),
                        data_id: data_receipt.data_id,
                    },
                )? {
                    // There is already a receipt that is awaiting for the just received data.
                    // Removing this pending data_id for the receipt from the state.
                    state_update.remove(TrieKey::PostponedReceiptId {
                        receiver_id: account_id.clone(),
                        data_id: data_receipt.data_id,
                    });
                    // Checking how many input data items is pending for the receipt.
                    let pending_data_count: u32 = get(
                        state_update,
                        &TrieKey::PendingDataCount { receiver_id: account_id.clone(), receipt_id },
                    )?
                    .ok_or_else(|| {
                        StorageError::StorageInconsistentState(
                            "pending data count should be in the state".to_string(),
                        )
                    })?;
                    if pending_data_count == 1 {
                        // It was the last input data pending for this receipt. We'll cleanup
                        // some receipt related fields from the state and execute the receipt.

                        // Removing pending data count from the state.
                        state_update.remove(TrieKey::PendingDataCount {
                            receiver_id: account_id.clone(),
                            receipt_id,
                        });
                        // Fetching the receipt itself.
                        let ready_receipt =
                            get_postponed_receipt(state_update, account_id, receipt_id)?
                                .ok_or_else(|| {
                                    StorageError::StorageInconsistentState(
                                        "pending receipt should be in the state".to_string(),
                                    )
                                })?;
                        // Removing the receipt from the state.
                        remove_postponed_receipt(state_update, account_id, receipt_id);
                        // Executing the receipt. It will read all the input data and clean it up
                        // from the state.
                        return self
                            .apply_action_receipt(
                                state_update,
                                apply_state,
                                pipeline_manager,
                                &ready_receipt,
                                receipt_sink,
                                instant_receipts,
                                validator_proposals,
                                stats,
                                epoch_info_provider,
                                receipt_to_tx,
                            )
                            .map(Some);
```

**File:** integration-tests/src/tests/standard_cases/mod.rs (L852-861)
```rust
    assert_eq!(
        transaction_result.status,
        FinalExecutionStatus::Failure(
            ActionError {
                index: Some(0),
                kind: ActionErrorKind::AccountAlreadyExists { account_id: eve_dot_alice_account() }
            }
            .into()
        )
    );
```
