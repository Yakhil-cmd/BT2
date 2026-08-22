### Title
Insolvent accounts can be permanently locked out of self-recovery actions (DeleteKey/DeleteAccount) due to unconditional pre-execution storage-stake check - (File: `runtime/runtime/src/verifier.rs`)

### Summary
`verify_and_charge_tx_ephemeral` runs `check_storage_stake` against the account's storage usage *before* any action in the transaction executes, using the balance remaining after the transaction cost is deducted. This mirrors the Cozy Finance bug class: an owner/controller is blocked from making config-fixing changes once a "position" (here, an account) is insolvent, because the pre-check does not distinguish between actions that would *increase* risk and actions (like `DeleteKey`/`DeleteAccount`) that would *reduce or eliminate* the storage-staking shortfall.

### Finding Description
`check_storage_stake` computes `required_amount = storage_amount_per_byte * account.storage_usage()` and compares it against the account's available balance [1](#0-0) . This function is invoked unconditionally inside `verify_and_charge_tx_ephemeral`, which is the pre-execution gate that decides whether a transaction is even converted into a receipt: it checks `check_storage_stake(account, new_amount, config)` where `account` still has its *pre-action* `storage_usage()`, and fails the whole transaction with `InvalidTxError::LackBalanceForState` if that check fails, before any action (including `DeleteKey` or `DeleteAccount`) has had a chance to run [2](#0-1) .

There is no special-casing for `DeleteAccount` or `DeleteKey` actions in this verifier path — a grep of `runtime/runtime/src/verifier.rs` for `DeleteAccount` found no matches, confirming the check is applied identically regardless of which actions the transaction contains.

By contrast, the actual execution-time code paths do treat these recovery actions specially:
- `action_delete_account` never calls `check_storage_stake` at all — it unconditionally proceeds to remove the account and refund its balance [3](#0-2) .
- The post-execution check in `apply()` in `lib.rs` re-checks `check_storage_stake` only *after* actions have executed, using the updated (post-action) `storage_usage()` [4](#0-3) .
- The design intent, as documented, is explicit: *"Account can end up with not enough balance in case it gets slashed... The only way to recover it in this case is by sending extra funds from a different accounts."* and the pseudocode explicitly special-cases `DeleteAccount(tx.signer_id) in tx.actions` in the transaction-verification logic [5](#0-4) .

The implementation in `verify_and_charge_tx_ephemeral`, however, does not implement this documented exemption for the tx-level pre-check. Since this check runs before actions execute and uses the *old* storage usage, an already-insolvent account cannot get a `DeleteKey` transaction (intended to shrink storage usage below its balance-backed limit) or a `DeleteAccount` transaction included/verified at all: the transaction is rejected as `InvalidTx` with `LackBalanceForState` at the pre-check stage, so the recovery action never reaches `action_delete_key`/`action_delete_account`, which are the only code paths that would actually reduce or eliminate the debt.

This is the direct nearcore analog of the Cozy Finance bug: an account owner cannot self-remediate an insolvent/over-limit state because a pre-condition check blocking "risk-increasing" changes is applied uniformly to "risk-reducing" changes as well, permanently locking the account unless outside funds are injected — exactly the scenario the docs claim is the *only* recovery path, but which the doc's own pseudocode suggested should have a carve-out for `DeleteAccount` that does not appear implemented in this verifier function.

### Impact Explanation
An account whose storage usage exceeds what its balance can cover (e.g., due to slashing, a state-usage-increasing receipt, or protocol/fee changes) becomes permanently unable to submit any transaction from itself, including the two actions (`DeleteKey`, `DeleteAccount`) that would shrink its storage footprint or remove it entirely and refund the remaining balance. This is a Denial-of-Service on the account's own recovery/exit path and can result in funds becoming permanently unreachable except via third-party funding, causing a real loss-of-access impact for the affected account holder. It does not, however, allow an attacker to steal funds or inflate tokens — the impact is limited to self-inflicted/adversarially-inflicted account lockout for the affected account and matches only a "state stuck" class of impact, not a chain-wide safety or inflation issue.

### Likelihood Explanation
This requires an account to first become insolvent for storage staking (e.g. via slashing per the docs, or via any process that increases `storage_usage()` while balance stays fixed) — this is an existing state that the codebase explicitly acknowledges can occur, and once it occurs, the lockout described above is deterministic and always reproducible for that account. No additional attacker capability beyond normal transaction submission is needed to trigger the confirmed inability to recover.

### Recommendation
Add a documented exemption in `verify_and_charge_tx_ephemeral` (and any other pre-execution/transaction-to-receipt verification path that calls `check_storage_stake`) analogous to `action_delete_account`'s behavior: skip or relax the storage-stake pre-check when the transaction's actions are exclusively storage-reducing/exit actions (`DeleteKey`, `DeleteAccount`), deferring the authoritative check to the post-execution check already present in `lib.rs`. This restores the account-recovery guarantee that the design docs claim exists.

### Proof of Concept
1. Create an account and artificially reduce its balance/increase storage usage until `check_storage_stake` fails for its current balance (e.g. via slashing simulation, matching the setup pattern used in `test_validate_transaction_invalid_low_balance_many_keys` in `runtime/runtime/src/verifier.rs`, lines 1474-1525).
2. Submit a `DeleteKey` transaction from that account intended to remove enough keys/data to bring `storage_usage()` back under the balance-supported limit.
3. Observe that `verify_and_charge_tx_ephemeral` rejects the transaction with `InvalidTxError::LackBalanceForState` before the `DeleteKey` action is ever executed (per the check at lines 330-343 of `verifier.rs`), because the check uses the account's storage usage as it stood before the `DeleteKey` action runs.
4. Confirm the account remains permanently unable to submit any self-originating transaction, including `DeleteAccount`, contradicting the documented recovery guarantee in `docs/Economics/Economics.md`.

### Citations

**File:** runtime/runtime/src/verifier.rs (L47-82)
```rust
pub fn check_storage_stake(
    account: &Account,
    account_balance: Balance,
    runtime_config: &RuntimeConfig,
) -> Result<(), StorageStakingError> {
    let billable_storage_bytes = account.storage_usage();
    let required_amount = runtime_config
        .storage_amount_per_byte()
        .checked_mul(u128::from(billable_storage_bytes))
        .ok_or_else(|| {
            format!(
                "Account's billable storage usage {} overflows multiplication",
                billable_storage_bytes
            )
        })
        .map_err(StorageStakingError::StorageError)?;
    let available_amount = account_balance
        .checked_add(account.locked())
        .ok_or_else(|| {
            format!(
                "Account's amount {} and locked {} overflow addition",
                account.amount(),
                account.locked(),
            )
        })
        .map_err(StorageStakingError::StorageError)?;
    if available_amount >= required_amount {
        Ok(())
    } else {
        if is_zero_balance_account(account) {
            return Ok(());
        }
        Err(StorageStakingError::LackBalanceForStorageStaking(
            required_amount.checked_sub(available_amount).unwrap(),
        ))
    }
```

**File:** runtime/runtime/src/verifier.rs (L330-343)
```rust
    };

    match check_storage_stake(account, new_amount, config) {
        Ok(()) => {}
        Err(StorageStakingError::LackBalanceForStorageStaking(amount)) => {
            return TxVerdict::Failed(InvalidTxError::LackBalanceForState {
                signer_id: account_id.clone(),
                amount,
            });
        }
        Err(StorageStakingError::StorageError(err)) => {
            return TxVerdict::Failed(StorageError::StorageInconsistentState(err).into());
        }
    };
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

**File:** runtime/runtime/src/lib.rs (L875-898)
```rust
        // Going to check balance covers account's storage.
        if result.result.is_ok() {
            if let Some(ref account) = account {
                match check_storage_stake(account, account.amount(), &apply_state.config) {
                    Ok(()) => {
                        set_account(state_update, account_id.clone(), account);
                    }
                    Err(StorageStakingError::LackBalanceForStorageStaking(amount)) => {
                        result.set_error(ActionError {
                            index: None,
                            kind: ActionErrorKind::LackBalanceForState {
                                account_id: account_id.clone(),
                                amount,
                            },
                        });
                    }
                    Err(StorageStakingError::StorageError(err)) => {
                        return Err(RuntimeError::StorageError(
                            StorageError::StorageInconsistentState(err),
                        ));
                    }
                }
            }
        }
```

**File:** docs/Economics/Economics.md (L79-101)
```markdown
# Check when transaction is received to verify that it is valid.
def verify_transaction(tx, signer_account):
    # ...
    # Updates signer's account with the amount it will have after executing this tx.
    update_post_amount(signer_account, tx)
    result = check_storage_cost(signer_account)
    # If enough balance OR account is been deleted by the owner.
    if not result.ok() or DeleteAccount(tx.signer_id) in tx.actions:
        assert LackBalanceForState(signer_id: tx.signer_id, amount: result.err())

# After account touched / changed, we check it still has enough balance to cover it's storage.
def on_account_change(block_height, account):
    # ... execute transaction / receipt changes ...
    # Validate post-condition and revert if it fails.
    result = check_storage_cost(sender_account)
    if not result.ok():
        assert LackBalanceForState(signer_id: tx.signer_id, amount: result.err())
```

Where `sizeOf(account)` includes size of `account_id`, `account` structure and size of all the data stored under the account.

Account can end up with not enough balance in case it gets slashed. Account will become unusable as all originating transactions will fail (including deletion).
The only way to recover it in this case is by sending extra funds from a different accounts.
```
