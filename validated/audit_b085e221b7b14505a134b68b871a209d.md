[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/sui-core/src/accumulators/funds_read.rs (L30-36)
```rust
    /// Read the amount at a precise version. Care must be taken to only call this function if we
    /// can guarantee that objects behind this version have not yet been pruned.
    fn get_account_amount_at_version(
        &self,
        account_id: &AccumulatorObjId,
        version: SequenceNumber,
    ) -> u128;
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L268-285)
```rust
        let last_settled_version = *self.last_settled_version_receiver.borrow();
        if accumulator_version <= last_settled_version {
            // If the version we are withdrawing from is already settled, we have all the information
            // we need to determine if the funds are sufficient or not.
            if self.try_withdraw(
                funds_read,
                &object_running_max_withdraws,
                &unsettled_withdraw_updates,
                accumulator_version,
            ) {
                return ObjectFundsWithdrawStatus::SufficientFunds;
            } else {
                let (sender, receiver) = oneshot::channel();
                // unwrap is safe because the receiver is defined right above.
                sender.send(FundsWithdrawStatus::Insufficient).unwrap();
                return ObjectFundsWithdrawStatus::Pending(receiver);
            }
        }
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L313-321)
```rust
    fn try_withdraw(
        &self,
        funds_read: &dyn AccountFundsRead,
        object_running_max_withdraws: &BTreeMap<AccumulatorObjId, u128>,
        unsettled_withdraw_updates: &BTreeMap<AccumulatorObjId, u128>,
        accumulator_version: SequenceNumber,
    ) -> bool {
        for (obj_id, amount) in object_running_max_withdraws {
            let funds = funds_read.get_account_amount_at_version(obj_id, accumulator_version);
```
