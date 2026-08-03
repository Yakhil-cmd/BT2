[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** mempool/src/core_mempool/transaction_store.rs (L266-303)
```rust
        if let Some(txns) = self.transactions.get_mut(&address) {
            if let Some(current_version) = txns.get_mut(&txn_replay_protector) {
                if current_version.txn.payload() != txn.txn.payload() {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a different payload".to_string(),
                    );
                } else if current_version.txn.expiration_timestamp_secs()
                    != txn.txn.expiration_timestamp_secs()
                {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a different expiration timestamp"
                            .to_string(),
                    );
                } else if current_version.txn.max_gas_amount() != txn.txn.max_gas_amount() {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a different max gas amount"
                            .to_string(),
                    );
                } else if current_version.get_gas_price() < txn.get_gas_price() {
                    // Update txn if gas unit price is a larger value than before
                    if let Some(txn) = txns.remove(&txn_replay_protector) {
                        self.index_remove(&txn);
                    };
                    counters::CORE_MEMPOOL_GAS_UPGRADED_TXNS.inc();
                } else if current_version.get_gas_price() > txn.get_gas_price() {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a higher gas price".to_string(),
                    );
                } else {
                    // If the transaction is the same, it's an idempotent call
                    // Updating signers is not supported, the previous submission must fail
                    counters::CORE_MEMPOOL_IDEMPOTENT_TXNS.inc();
                    if let Some(acc_seq_num) = account_sequence_number {
                        self.process_ready_seq_num_based_transactions(&address, acc_seq_num);
                    }
                    return MempoolStatus::new(MempoolStatusCode::Accepted);
                }
            }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L306-319)
```rust
        if let ReplayProtector::SequenceNumber(txn_seq_num) = txn.get_replay_protector() {
            let acc_seq_num = account_sequence_number.expect(
                "Account sequence number is always provided for transactions with sequence number",
            );
            self.clean_committed_transactions_below_account_seq_num(&address, acc_seq_num);
            if txn_seq_num < acc_seq_num {
                return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber).with_message(
                    format!(
                        "transaction sequence number is {}, current sequence number is  {}",
                        txn_seq_num, acc_seq_num,
                    ),
                );
            }
        }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L914-922)
```rust
    /// Garbage collect old transactions.
    pub(crate) fn gc_by_system_ttl(&mut self, gc_time: Duration) {
        self.gc(gc_time, true);
    }

    /// Garbage collect old transactions based on client-specified expiration time.
    pub(crate) fn gc_by_expiration_time(&mut self, block_time: Duration) {
        self.gc(self.eager_expire_time(block_time), false);
    }
```

**File:** vm-validator/src/vm_validator.rs (L143-170)
```rust
impl TransactionValidation for PooledVMValidator {
    type ValidationInstance = AptosVM;

    fn validate_transaction(&self, txn: SignedTransaction) -> Result<VMValidatorResult> {
        let vm_validator = self.get_next_vm();

        fail_point!("vm_validator::validate_transaction", |_| {
            Err(anyhow::anyhow!(
                "Injected error in vm_validator::validate_transaction"
            ))
        });

        let result = std::panic::catch_unwind(move || {
            let vm_validator_locked = vm_validator.lock().unwrap();

            use aptos_vm::VMValidator;
            let vm = AptosVM::new(&vm_validator_locked.state.environment);
            vm.validate_transaction(
                txn,
                &vm_validator_locked.state.state_view,
                &vm_validator_locked.state,
            )
        });
        if let Err(err) = &result {
            error!("VMValidator panicked: {:?}", err);
        }
        result.map_err(|_| anyhow::anyhow!("panic validating transaction"))
    }
```
