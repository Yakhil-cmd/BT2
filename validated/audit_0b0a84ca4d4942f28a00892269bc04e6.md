## Finding

### Title
TOCTOU in `Bank::resanitize_transaction_minimally`: ALT re-validation discards resolved addresses, so execution uses stale cached account bindings - (File: `runtime/src/bank.rs`)

### Summary
`Bank::resanitize_transaction_minimally` re-checks a buffered/pre-sanitized transaction's address-lookup-table (ALT) validity before scheduling it for execution. When the ALT invalidation slot has passed, it re-resolves the lookup table and only checks that resolution *succeeds* — it explicitly discards the newly resolved addresses (`let (_addresses, _deactivation_slot) = ...`) instead of comparing them against the addresses that were cached in the transaction at the original Time-of-Check (`translate_to_runtime_view` / `precheck_transaction` in the banking-stage receive path). This is the same "check the current file, execute the cached memory" pattern described in the external report: the validity check is performed against fresh on-chain ALT state, but the accounts that actually get locked and executed are the stale ones resolved earlier and stored inside the `ResolvedTransactionView`.

### Finding Description
The transaction ingestion path resolves ALT addresses once, early, against a `root_bank`, and bakes them into the `RuntimeTransaction<ResolvedTransactionView<..>>`: [1](#0-0) 

That transaction, together with a `MaxAge{ sanitized_epoch, alt_invalidation_slot }`, is buffered in the scheduler and later replayed for consumption at execution time by `process_and_record_aged_transactions`, which calls `resanitize_transaction_minimally`: [2](#0-1) 

The re-check itself: [3](#0-2) 

Note the comment's own reasoning: *"If the addresses still resolve here, then the transaction is still valid, and we can continue with processing."* The code re-resolves the ALT lookups from the *current* bank state (Time-of-Check) but throws away the result (`_addresses`) and keeps using the transaction's originally cached, pre-resolved account keys (Time-of-Use) for locking (`prepare_sanitized_batch_with_results`) and for the entire SVM execution pipeline. The check never asserts that the freshly-resolved addresses are identical to the ones embedded in the transaction at sanitization time.

This design implicitly assumes ALT entries are immutable once written at a given index (true for a normal `extend`-only lifecycle), but the address-lookup-table program allows an account to be fully deactivated and closed, and a new lookup table to be created at the exact same derived PDA (same `authority` + same `recent_slot` seeds) with entirely different address contents at the same indices. If that recreation happens while a transaction referencing that ALT is sitting in the banking-stage container (buffered between root-bank sanitization and leader-slot execution), the "still resolves" check on the *new* table content will pass, letting a transaction execute whose actual account keys were bound to the *old* (now-defunct) table contents — a divergence between what was validated and what actually gets locked/executed.

### Impact Explanation
Because account locking (`prepare_sanitized_batch_with_results`) and SVM execution both use the transaction's cached, unverified account-key set rather than the freshly-checked resolution, a validator can be induced to execute (and, by extension, other validators replaying the same block must also execute) an instruction set whose account bindings no longer correspond to any currently-resolvable, consensus-agreed ALT state. This weakens the intended safety property of `resanitize_transaction_minimally` (dropping transactions whose ALT-based bindings are no longer valid) and can allow transactions to be included/executed against stale account bindings that should have been rejected, undermining the check's purpose as a re-validation gate for banking-stage-buffered, unprivileged, user-submitted transactions.

### Likelihood Explanation
Reaching this path only requires submitting an ordinary versioned (V0) transaction referencing an address lookup table the sender controls, timed so that: (1) the transaction is received and pre-sanitized/buffered by the banking stage against an earlier bank, (2) the ALT is deactivated and closed, and a new table is created at the same address with different contents, and (3) the transaction is later dequeued for execution once `slot() > alt_invalidation_slot`. This is entirely reachable by a single unprivileged transaction sender manipulating their own ALT lifecycle and transaction submission timing, with no special validator/leader/network privileges required, though it requires precise timing around the ALT deactivation window and the scheduler's re-check cadence (`incremental_recheck` / `process_and_record_aged_transactions`).

### Recommendation
In `resanitize_transaction_minimally`, compare the freshly-resolved `LoadedAddresses` against the ones already embedded in the transaction (or re-derive the `ResolvedTransactionView` account keys) rather than discarding the freshly-resolved values; reject the transaction (`TransactionError::AddressLookupTableNotFound`/equivalent) if they differ, instead of only checking that resolution succeeds.

### Proof of Concept
1. Attacker creates an address lookup table `T` at PDA derived from `(authority, recent_slot=S)`, populates it with address `A_evil` at index 0.
2. Attacker submits a V0 transaction referencing `T` at index 0; it's received and buffered by banking stage — `translate_to_runtime_view` resolves index 0 to `A_evil` and caches it in the `ResolvedTransactionView`; `MaxAge.alt_invalidation_slot` is set based on `T`'s (non-deactivated) state.
3. Before the transaction is scheduled for consumption, attacker deactivates `T`, waits out the deactivation window, and closes it, then creates a new table at the same PDA `(authority, recent_slot=S)` with `A_benign` (or any different address) at index 0.
4. When the scheduler later reaches this transaction (`slot() > alt_invalidation_slot`), `resanitize_transaction_minimally` re-resolves `T`'s lookups, gets `Ok((A_benign_addresses, ...))`, discards the result, and returns `Ok(())` — the transaction is accepted for execution using the originally cached `A_evil` binding despite the underlying ALT having been fully replaced in the interim.

### Citations

**File:** core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs (L120-161)
```rust
pub(crate) fn translate_to_runtime_view<D: TransactionData>(
    data: D,
    bank: &Bank,
    transaction_account_lock_limit: usize,
    sanitize_config: &SanitizeConfig,
) -> Result<(RuntimeTransaction<ResolvedTransactionView<D>>, u64), PacketHandlingError> {
    let Ok(view) = SanitizedTransactionView::try_new_sanitized(data, sanitize_config) else {
        return Err(PacketHandlingError::Sanitization);
    };

    let Ok(view) = RuntimeTransaction::<SanitizedTransactionView<_>>::try_new(
        view,
        MessageHash::Compute,
        None,
    ) else {
        return Err(PacketHandlingError::Sanitization);
    };

    if bank.vote_only_bank() && !view.is_simple_vote_transaction() {
        return Err(PacketHandlingError::Sanitization);
    }

    if usize::from(view.total_num_accounts()) > transaction_account_lock_limit {
        return Err(PacketHandlingError::LockValidation);
    }

    let (loaded_addresses, deactivation_slot) = load_addresses_for_view(&view, bank)?;

    let Ok(view) = RuntimeTransaction::<ResolvedTransactionView<_>>::try_new(
        view,
        loaded_addresses,
        bank.get_reserved_account_keys(),
    ) else {
        return Err(PacketHandlingError::Sanitization);
    };

    if validate_account_locks(view.account_keys(), transaction_account_lock_limit).is_err() {
        return Err(PacketHandlingError::LockValidation);
    }

    Ok((view, deactivation_slot))
}
```

**File:** core/src/banking_stage/consumer.rs (L173-191)
```rust
    pub fn process_and_record_aged_transactions(
        &self,
        bank: &Bank,
        txs: &[impl TransactionWithMeta],
        max_ages: &[MaxAge],
        flags: &ExecutionFlags,
    ) -> ProcessTransactionBatchOutput {
        // Need to filter out transactions since they were sanitized earlier.
        // This means that the transaction may cross and epoch boundary (not allowed),
        //  or account lookup tables may have been closed.
        let pre_results = txs.iter().zip(max_ages).map(|(tx, max_age)| {
            bank.resanitize_transaction_minimally(
                tx,
                max_age.sanitized_epoch,
                max_age.alt_invalidation_slot,
            )
        });
        self.process_and_record_transactions_with_pre_results(bank, txs, pre_results, flags)
    }
```

**File:** runtime/src/bank.rs (L3910-3947)
```rust
    pub fn resanitize_transaction_minimally(
        &self,
        transaction: &impl TransactionWithMeta,
        sanitized_epoch: Epoch,
        alt_invalidation_slot: Slot,
    ) -> Result<()> {
        if self.vote_only_bank() && !vote_parser::is_valid_vote_only_transaction(transaction) {
            return Err(TransactionError::SanitizeFailure);
        }

        // If the transaction was sanitized before this bank's epoch,
        // additional checks are necessary.
        if self.epoch() != sanitized_epoch {
            // Reserved key set may have changed, so we must verify that
            // no writable keys are reserved.
            self.check_reserved_keys(transaction)?;

            for instr in transaction.instructions_iter() {
                if instr.accounts.len() > solana_transaction_context::MAX_ACCOUNTS_PER_INSTRUCTION {
                    return Err(solana_transaction_error::TransactionError::SanitizeFailure);
                }
            }
        }

        if self.slot() > alt_invalidation_slot {
            // The address table lookup **may** have expired, but the
            // expiration is not guaranteed since there may have been
            // skipped slot.
            // If the addresses still resolve here, then the transaction is still
            // valid, and we can continue with processing.
            // If they do not, then the ATL has expired and the transaction
            // can be dropped.
            let (_addresses, _deactivation_slot) =
                self.load_addresses_from_ref(transaction.message_address_table_lookups())?;
        }

        Ok(())
    }
```
