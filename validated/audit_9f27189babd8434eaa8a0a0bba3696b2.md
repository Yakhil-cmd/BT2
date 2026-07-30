[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-core/src/execution_scheduler/funds_withdraw_scheduler/address_funds/scheduler.rs (L109-111)
```rust
    /// This function will be called at most once per consensus commit batch that all reads the same root accumulator version.
    /// If a consensus commit batch does not contain any withdraw reservations, it can skip calling this function.
    /// It must be called sequentially in order to correctly schedule withdraws.
```

**File:** crates/sui-core/src/execution_scheduler/funds_withdraw_scheduler/address_funds/scheduler.rs (L137-155)
```rust
    async fn process_withdraw_task(
        scheduler: Arc<dyn FundsWithdrawSchedulerTrait>,
        mut withdraw_receiver: UnboundedReceiver<WithdrawEvent>,
        metrics: Arc<AddressFundsSchedulerMetrics>,
    ) {
        while let Some(event) = withdraw_receiver.recv().await {
            let WithdrawEvent {
                reservations,
                mut senders,
            } = event;
            debug!(
                withdraw_accumulator_version =? reservations.accumulator_version.value(),
                "Processing withdraws: {:?}",
                reservations.withdraws,
            );

            let num_txns = reservations.withdraws.len();
            let accumulator_version = reservations.accumulator_version;
            let results = scheduler.schedule_withdraws(reservations);
```
