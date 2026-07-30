[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/sui-types/src/inner_temporary_store.rs (L40-48)
```rust
    /// For each accumulator account, tracks the max running net withdraws during this transaction.
    /// For instance, if the funds accumulator events looke like this for an account:
    /// - Split(100)
    /// - Merge(100)
    /// - Split(100)
    ///
    /// Then the accumulator_running_max_withdraws for this account will be 100,
    /// because at any given moment, the net withdraws is at most 100.
    pub accumulator_running_max_withdraws: BTreeMap<AccumulatorObjId, u128>,
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L132-177)
```rust
        // The sufficiency check must use the running max withdraws (the peak withdraw
        // exposure at any point during execution), but the amount that settlement will
        // actually deduct from each account is the net amount recorded in the effects.
        // E.g. a tx that withdraws 10 and deposits 10 back has a running max of 10 but
        // nets to 0. Recording the running max as unsettled would over-count against
        // other withdraws in the same consensus commit.
        let unsettled_withdraw_updates = if epoch_store
            .protocol_config()
            .record_net_unsettled_object_withdraws()
        {
            let updates: BTreeMap<_, _> = effects
                .accumulator_events()
                .into_iter()
                .filter(|event| !address_funds_reservations.contains(&event.accumulator_obj))
                .filter_map(|event| {
                    event
                        .write
                        .get_fund_withdraw_amount()
                        // A zero-amount withdraw emits a single Split(0) accumulator event,
                        // which survives effects folding as a Split (the fold's Merge
                        // tie-break only applies when an account has multiple writes).
                        // It contributes nothing to the running max nor to settlement,
                        // so recording it would be a no-op; skip it.
                        .filter(|amount| *amount > 0)
                        .map(|amount| (event.accumulator_obj, amount))
                })
                .collect();
            // A positive net withdraw in effects implies a positive peak, so the account
            // must have a running max entry that the net cannot exceed. Recording more
            // than what the sufficiency check covered could break the
            // funds >= unsettled_withdraw invariant in try_withdraw.
            debug_assert!(
                updates.iter().all(|(obj_id, net)| {
                    object_running_max_withdraws
                        .get(obj_id)
                        .is_some_and(|max| net <= max)
                }),
                "net withdraw exceeds running max: tx={:?} updates={:?} running_max={:?}",
                certificate.digest(),
                updates,
                object_running_max_withdraws,
            );
            updates
        } else {
            object_running_max_withdraws.clone()
        };
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L320-343)
```rust
        for (obj_id, amount) in object_running_max_withdraws {
            let funds = funds_read.get_account_amount_at_version(obj_id, accumulator_version);
            // Reading inner without a top-level lock is safe because no two transactions can be withdrawing
            // from the same account at the same time.
            let unsettled_withdraw = self
                .inner
                .read()
                .unsettled_withdraws
                .get(obj_id)
                .and_then(|withdraws| withdraws.get(&accumulator_version))
                .copied()
                .unwrap_or_default();
            debug!(
                ?obj_id,
                ?funds,
                ?accumulator_version,
                ?unsettled_withdraw,
                ?amount,
                "Trying to withdraw"
            );
            assert!(funds >= unsettled_withdraw);
            if funds - unsettled_withdraw < *amount {
                return false;
            }
```
