### Title
Concurrent Fee Transfer Commit Phase Overwrites Execution-Phase Sequencer Balance Writes, Causing Incorrect Committed State - (`crates/blockifier/src/concurrency/fee_utils.rs`)

### Summary

In concurrent execution mode, when a transaction transfers tokens to the sequencer address during its `__execute__` phase AND pays a fee, the `complete_fee_transfer_flow` commit-phase function overwrites the execution-phase sequencer balance write with only the fee amount. The execution-phase transfer is silently lost from the committed state.

### Finding Description

The blockifier's concurrent fee transfer uses a deliberate two-phase design to avoid read-set contamination on the sequencer balance:

**Phase 1 – Execution (`concurrency_execute_fee_transfer`):**
The fee transfer is executed against a sub-transactional state where the sequencer balance is forced to `Felt::ZERO`. After the ERC20 `transfer` call completes, the sequencer balance writes are explicitly removed before committing the sub-state back to the outer state: [1](#0-0) 

This means the outer transaction state retains any sequencer balance write that came from the user's own `__execute__` logic (e.g., an explicit ERC20 transfer to the sequencer address), but the fee-transfer-induced write is stripped.

**Phase 2 – Commit (`complete_fee_transfer_flow` → `add_fee_to_sequencer_balance`):**
At commit time, the actual sequencer balance is read from `tx_versioned_state`, which reflects only previously committed transactions and **does not include the current transaction's own writes**: [2](#0-1) 

`add_fee_to_sequencer_balance` then computes `balance_from_versioned_state + fee` and writes it back via `state.apply_writes(...)` and `state_diff.storage.insert(...)`: [3](#0-2) 

Both `apply_writes` on the versioned state and `HashMap::insert` on the state diff overwrite any existing entry for the sequencer balance key. The execution-phase write of `balance_before + transfer_amount` is replaced with `balance_before + fee`.

**The broken invariant:** The design assumes the only sequencer balance modification during execution is the fee transfer (which is explicitly stripped). When a user's `__execute__` body also writes to the sequencer balance (a valid, unprivileged operation), that write is silently discarded at commit time.

The test `test_concurrency_execute_fee_transfer` (Case 2) explicitly demonstrates that after `execute_raw` in concurrent mode the sequencer balance write is `SEQUENCER_BALANCE_LOW_INITIAL + TRANSFER_AMOUNT`, but no test verifies the state after `commit_tx` in this scenario: [4](#0-3) 

The commit-phase test `test_commit_tx` only covers transactions that do not transfer to the sequencer during execution: [5](#0-4) 

### Impact Explanation

The committed block state has an incorrect (understated) sequencer fee token balance. Specifically, the sequencer's balance is `balance_before + fee` instead of `balance_before + transfer_amount + fee`. The `transfer_amount` tokens are deducted from the user's account (the ERC20 transfer executed correctly) but are never credited to the sequencer — they are effectively burned. This is a wrong storage value committed from blockifier execution logic for a valid, accepted input transaction, with direct economic impact on the sequencer's fee token balance.

### Likelihood Explanation

Concurrent mode is a production feature used by `WorkerExecutor`. Any unprivileged user can craft an invoke transaction whose calldata calls the fee token contract's `transfer` function targeting the sequencer address before the automatic fee transfer occurs. No special permissions are required. The trigger is a standard ERC20 transfer syscall available to all accounts.

### Recommendation

In `complete_fee_transfer_flow`, instead of reading the sequencer balance exclusively from the versioned state (which excludes the current transaction's writes), also incorporate any sequencer balance write already present in `execution_output.state_diff`. Concretely, before calling `add_fee_to_sequencer_balance`, check whether `execution_output.state_diff.storage` already contains an entry for `(fee_token_address, sequencer_balance_key_low/high)` and use that as the base balance rather than the versioned-state read. This ensures execution-phase transfers to the sequencer are preserved when the fee is added on top.

### Proof of Concept

1. Enable concurrent execution mode (`WorkerExecutor`).
2. Fund account `A` with `BALANCE` STRK tokens. Let the sequencer's initial balance be `S`.
3. Submit an invoke transaction from `A` whose calldata:
   - Calls `fee_token.transfer(sequencer_address, TRANSFER_AMOUNT)` (e.g., 100 STRK).
   - Pays a normal fee `F`.
4. After `commit_tx` completes, read the sequencer's fee token balance from the versioned state at `tx_index`.
5. **Expected:** `S + TRANSFER_AMOUNT + F`
6. **Actual:** `S + F` — the `TRANSFER_AMOUNT` is lost.

The existing test infrastructure in `crates/blockifier/src/concurrency/worker_logic_test.rs` can be extended by adding a transaction that transfers to the sequencer during execution (analogous to Case 2 in `test_concurrency_execute_fee_transfer`) and then calling `commit_tx`, verifying the sequencer balance includes both the transfer and the fee. [6](#0-5) [7](#0-6)

### Citations

**File:** crates/blockifier/src/transaction/account_transaction.rs (L607-622)
```rust
        let mut transfer_state = TransactionalState::create_transactional(state);

        // Set the initial sequencer balance to avoid tarnishing the read-set of the transaction.
        let cache = transfer_state.cache.get_mut();
        for key in [sequencer_balance_key_low, sequencer_balance_key_high] {
            cache.set_storage_initial_value(fee_address, key, Felt::ZERO);
        }

        let fee_transfer_call_info =
            Self::execute_fee_transfer(&mut transfer_state, tx_context, actual_fee);
        // Commit without updating the sequencer balance.
        let storage_writes = &mut transfer_state.cache.get_mut().writes.storage;
        storage_writes.remove(&(fee_address, sequencer_balance_key_low));
        storage_writes.remove(&(fee_address, sequencer_balance_key_high));
        transfer_state.commit();
        fee_transfer_call_info
```

**File:** crates/blockifier/src/concurrency/fee_utils.rs (L26-74)
```rust
pub fn complete_fee_transfer_flow(
    tx_context: &TransactionContext,
    tx_execution_info: &mut TransactionExecutionInfo,
    state_diff: &mut StateMaps,
    state: &mut impl UpdatableState,
    tx: &Transaction,
) {
    if tx_context.is_sequencer_the_sender() {
        // When the sequencer is the sender, we use the sequential (full) fee transfer.
        return;
    }

    if let Some(fee_transfer_call_info) = tx_execution_info.fee_transfer_call_info.as_mut() {
        let sequencer_balance = state
        .get_fee_token_balance(
            tx_context.block_context.block_info.sequencer_address,
            tx_context.fee_token_address()
        )
        // TODO(barak, 01/07/2024): Consider propagating the error.
        .unwrap_or_else(|error| {
            panic!(
                "Access to storage failed. Probably due to a bug in Papyrus. {error:?}: {error}"
            )
        });

        // Fix the transfer call info.
        fill_sequencer_balance_reads(fee_transfer_call_info, sequencer_balance);
        // Update the balance.
        add_fee_to_sequencer_balance(
            tx_context.fee_token_address(),
            state,
            tx_execution_info.receipt.fee,
            &tx_context.block_context,
            sequencer_balance,
            tx_context.tx_info.sender_address(),
            state_diff,
        );
    } else {
        // Sanity check.
        match tx {
            Transaction::Account(tx) => assert!(
                !tx.execution_flags.charge_fee || tx_execution_info.receipt.fee == Fee(0),
                "Transaction with no fee transfer info must not enforce a fee charge."
            ),
            // No fee transfer info for L1 handler transactions.
            Transaction::L1Handler(_) => {}
        };
    }
}
```

**File:** crates/blockifier/src/concurrency/fee_utils.rs (L118-157)
```rust
    let (low, high) = sequencer_balance;
    let sequencer_balance_low_as_u128 =
        low.to_u128().expect("sequencer balance low should be u128");
    let sequencer_balance_high_as_u128 =
        high.to_u128().expect("sequencer balance high should be u128");
    let (new_value_low, overflow_low) = sequencer_balance_low_as_u128.overflowing_add(actual_fee.0);
    let (new_value_high, overflow_high) =
        sequencer_balance_high_as_u128.overflowing_add(overflow_low.into());
    assert!(
        !overflow_high,
        "The sequencer balance overflowed when adding the fee. This should not happen."
    );
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(block_context);
    let writes = StateMaps {
        storage: HashMap::from([
            ((fee_token_address, sequencer_balance_key_low), Felt::from(new_value_low)),
            ((fee_token_address, sequencer_balance_key_high), Felt::from(new_value_high)),
        ]),
        ..StateMaps::default()
    };

    // Modify state_diff to accurately reflect the post tx-execution state, after fee transfer to
    // the sequencer. We assume that a non-sequencer sender cannot reduce the sequencer's
    // balance—only increases are possible.

    if sequencer_balance_high_as_u128 != new_value_high {
        // Update the high balance only if it has changed.
        state_diff
            .storage
            .insert((fee_token_address, sequencer_balance_key_high), Felt::from(new_value_high));
    }

    if sequencer_balance_low_as_u128 != new_value_low {
        // Update the low balance only if it has changed.
        state_diff
            .storage
            .insert((fee_token_address, sequencer_balance_key_low), Felt::from(new_value_low));
    }
    state.apply_writes(&writes, &ContractClassMapping::default());
```

**File:** crates/blockifier/src/transaction/account_transactions_test.rs (L1880-1928)
```rust
    // Case 2: The transaction read from and write to the sequencer balance before executing fee
    // transfer.

    let transfer_calldata = create_calldata(
        fee_token_address,
        TRANSFER_ENTRY_POINT_NAME,
        &[*block_context.block_info.sequencer_address.0.key(), felt!(TRANSFER_AMOUNT), felt!(0_u8)],
    );

    // Set the sequencer balance to a constant value to check that the read set did not changed.
    fund_account(
        chain_info,
        block_context.block_info.sequencer_address,
        Fee(SEQUENCER_BALANCE_LOW_INITIAL),
        &mut state.state,
    );
    let mut transactional_state = TransactionalState::create_transactional(&mut state);

    // Invokes transfer to the sequencer.
    let account_tx = invoke_tx_with_default_flags(invoke_tx_args! {
        sender_address: account_address,
        calldata: transfer_calldata,
        max_fee,
        resource_bounds: default_all_resource_bounds,
    });

    let execution_result =
        account_tx.execute_raw(&mut transactional_state, &block_context, concurrency_mode);
    let result = execution_result.unwrap();
    assert!(!result.is_reverted());
    // Check that the sequencer balance was not updated.
    let storage_writes = transactional_state.cache.borrow().writes.storage.clone();
    let storage_initial_reads = transactional_state.cache.borrow().initial_reads.storage.clone();

    for (seq_write_val, expected_write_val) in [
        (
            storage_writes.get(&(fee_token_address, sequencer_balance_key_low)),
            // Balance after `execute` and without the fee transfer.
            felt!(SEQUENCER_BALANCE_LOW_INITIAL + TRANSFER_AMOUNT),
        ),
        (
            storage_initial_reads.get(&(fee_token_address, sequencer_balance_key_low)),
            felt!(SEQUENCER_BALANCE_LOW_INITIAL),
        ),
        (storage_writes.get(&(fee_token_address, sequencer_balance_key_high)), Felt::ZERO),
        (storage_initial_reads.get(&(fee_token_address, sequencer_balance_key_high)), Felt::ZERO),
    ] {
        assert_eq!(*seq_write_val.unwrap(), expected_write_val);
    }
```

**File:** crates/blockifier/src/concurrency/worker_logic_test.rs (L78-198)
```rust
#[rstest]
pub fn test_commit_tx() {
    let block_context = BlockContext::create_for_account_testing();
    let account =
        FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1(RunnableCairo1::Casm));
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut expected_sequencer_balance_low = 0_u128;
    let mut nonce_manager = NonceManager::default();
    let account_address = account.get_instance_address(0);
    let test_contract_address = test_contract.get_instance_address(0);
    let first_nonce = nonce_manager.next(account_address);
    let second_nonce = nonce_manager.next(account_address);

    // Create transactions.
    let txs = [
        trivial_calldata_invoke_tx(account_address, test_contract_address, first_nonce),
        trivial_calldata_invoke_tx(account_address, test_contract_address, second_nonce),
        trivial_calldata_invoke_tx(account_address, test_contract_address, second_nonce),
        // Invalid nonce.
        trivial_calldata_invoke_tx(account_address, test_contract_address, nonce!(10_u8)),
    ]
    .into_iter()
    .map(Transaction::Account)
    .collect::<Vec<Transaction>>();
    let bouncer = Bouncer::new(block_context.bouncer_config.clone());
    let cached_state =
        test_state(&block_context.chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
    let versioned_state = safe_versioned_state_for_testing(cached_state);
    let executor = WorkerExecutor::new(
        versioned_state,
        txs.to_vec(),
        block_context.into(),
        Mutex::new(bouncer).into(),
        None,
    );

    // Execute transactions.
    // Simulate a concurrent run by executing tx1 before tx0.
    // tx1 should fail execution since its nonce equals 1, and it is being executed before tx0,
    // whose nonce equals 0.
    // tx0 should pass execution.
    // tx2 should pass execution since its nonce equals 1, so executing it after tx0 should
    // succeed.
    // tx3 should fail execution regardless of execution order since its nonce
    // equals 10, where there are only four transactions.
    for &(execute_idx, should_fail_execution) in
        [(1, true), (0, false), (2, false), (3, true)].iter()
    {
        executor.execute_tx(execute_idx);
        let execution_task_outputs = executor.lock_execution_output(execute_idx);
        let result = &execution_task_outputs.result;
        assert_eq!(result.is_err(), should_fail_execution);
        if !should_fail_execution {
            assert!(!result.as_ref().unwrap().is_reverted());
        }
    }

    // Commit all transactions in sequential order.
    // * tx0 should pass revalidation, fix the sequencer balance, fix the call info (fee transfer)
    //   and commit.
    // * tx1 should fail revalidation (it read the nonce before tx0 incremented it). It should pass
    //   re-execution (since tx0 incremented the nonce), fix the sequencer balance, fix the call
    //   info (fee transfer) and commit.
    // * tx2 should fail revalidation (it read the nonce before tx1 re-executed and incremented it).
    //   It should fail re-execution because it has the same nonce as tx1.
    // * tx3 should pass revalidation and commit.
    for &(commit_idx, should_pass_validation, should_pass_execution) in
        [(0, true, true), (1, false, true), (2, false, false), (3, true, false)].iter()
    {
        // Manually set the status before calling `commit_tx` to simulate the behavior of
        // `try_commit`.
        executor.scheduler.set_tx_status(commit_idx, TransactionStatus::Committed);
        let commit_result = executor.commit_tx(commit_idx).unwrap();
        if should_pass_validation {
            assert_eq!(commit_result, CommitResult::Success);
        } else {
            assert_eq!(commit_result, CommitResult::ValidationFailed, "commit_idx: {commit_idx}");
            // Re-execute the transaction.
            executor.execute_tx(commit_idx);
            // Commit again. This time it should succeed.
            assert_eq!(executor.commit_tx(commit_idx).unwrap(), CommitResult::Success);
        }

        let execution_task_outputs = executor.lock_execution_output(commit_idx);
        let execution_result = &execution_task_outputs.result;
        let expected_sequencer_balance_high = 0_u128;
        assert_eq!(execution_result.is_ok(), should_pass_execution);
        // Extract the actual fee. If the transaction fails, no fee should be charged.
        let actual_fee = if should_pass_execution {
            execution_result.as_ref().unwrap().receipt.fee.0
        } else {
            0
        };
        if should_pass_execution {
            assert!(!execution_result.as_ref().unwrap().is_reverted());
            // Check that the call info was fixed.
            for (expected_sequencer_storage_read, read_storage_index) in [
                (expected_sequencer_balance_low, STORAGE_READ_SEQUENCER_BALANCE_INDICES.0),
                (expected_sequencer_balance_high, STORAGE_READ_SEQUENCER_BALANCE_INDICES.1),
            ] {
                let actual_sequencer_storage_read = execution_result
                    .as_ref()
                    .unwrap()
                    .fee_transfer_call_info
                    .as_ref()
                    .unwrap()
                    .storage_access_tracker
                    .storage_read_values[read_storage_index];
                assert_eq!(felt!(expected_sequencer_storage_read), actual_sequencer_storage_read,);
            }
        }
        let tx_context = executor.block_context.to_tx_context(&txs[commit_idx]);
        expected_sequencer_balance_low += actual_fee;
        // Check that the sequencer balance was updated correctly in the state.
        verify_sequencer_balance_update(
            &executor.state,
            &tx_context,
            commit_idx,
            expected_sequencer_balance_low,
        );
    }
```

**File:** crates/blockifier/src/concurrency/worker_logic.rs (L367-373)
```rust
            complete_fee_transfer_flow(
                &tx_context,
                tx_execution_info,
                &mut execution_output.state_diff,
                &mut tx_versioned_state,
                tx.as_ref(),
            );
```
