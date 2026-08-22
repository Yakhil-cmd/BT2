## Analysis

The Rubicon bug is fundamentally a **head-of-queue poison-pill DOS**: a malformed/unfillable item is admitted into an ordered, FIFO-processed structure, and every consumer of that structure that walks it in order gets permanently blocked or degraded by that one item. The nearcore analog exists in the **receipt size validation / congestion-control outgoing-buffer** subsystem, and it is already an acknowledged, reproducible issue in this exact repository (tracked as near/nearcore#12606), reachable purely from an unprivileged contract call — no validator or P2P access required.

### Title
Oversized receipts bypass `max_receipt_size` validation and corrupt bandwidth-grant accounting in the outgoing receipt buffer - (File: `runtime/runtime/src/congestion_control.rs`, `runtime/runtime/src/verifier.rs`)

### Summary
`validate_receipt` only enforces the `max_receipt_size` limit when a receipt is first created (`ValidateReceiptMode::NewReceipt`), but a contract can grow a receipt (e.g. via `output_data_receivers`, a large returned value wrapped into a `DataReceipt`, or `promise_return`) **after** that check, producing a receipt that is stored/forwarded despite exceeding `max_receipt_size`. This is explicitly documented as a live, unresolved bug in `ValidateReceiptMode::ExistingReceipt` [1](#0-0)  and reproduced by the repo's own tests [2](#0-1) [3](#0-2) .

### Finding Description
Receipt size is only checked strictly at creation time: [4](#0-3) . Once such a receipt exists in state (delayed queue or outgoing buffer), it is treated with `ValidateReceiptMode::ExistingReceipt`, which tolerates the size violation "until the receipt size limit bug is fixed" [1](#0-0) .

This oversized receipt then flows into the outgoing-receipt buffering/forwarding logic (`ReceiptSinkV2::try_forward` and `forward_from_buffer_to_shard`), which processes the FIFO buffer to a destination shard and **stops (`break`) at the first receipt that does not fit the current bandwidth grant** — exactly like Rubicon's `getBestOffer` head-of-list processing: [5](#0-4) .

Because a real oversized receipt could never fit under any legitimate bandwidth grant (grants are bounded by `max_single_grant`, which is asserted `>= max_receipt_size`), such a receipt sitting at the head of the buffer would permanently block every receipt behind it to that shard. The code contains an explicit acknowledgment of this and a partial mitigation that *pretends* the receipt is only `max_receipt_size` bytes for the purpose of the admission check: [6](#0-5) . The same pretend-clamping is duplicated in bandwidth-request generation: [7](#0-6) .

This clamping avoids the permanent stall, but it does so by admitting the receipt using a **falsified (smaller) size** for scheduling/admission purposes, while the receipt actually consumes real (larger) bandwidth/storage/network resources when forwarded. Since `own_congestion_info`/outgoing-limit accounting downstream is driven by this clamped comparison rather than the true size, an attacker-controlled oversized receipt is forwarded to a target shard while consuming more real bandwidth/witness bytes than the scheduler granted it — i.e., the bandwidth scheduler's fairness/anti-congestion accounting for that link is bypassed.

### Impact Explanation
This is directly analogous to the Rubicon finding: an attacker-crafted, protocol-invalid item is admitted into a FIFO-ordered resource queue and, absent (or only partially) the special-cased workaround, would deterministically stall all subsequent legitimate items destined for the same shard (chain-level liveness degradation targeted at a specific shard's inbound receipt stream), and even with the workaround in place it still lets a malicious contract exceed the shard-to-shard bandwidth grant it was actually given, undermining the congestion-control mechanism that exists specifically to bound per-block/per-shard resource consumption and prevent chunk witness bloat (see the documented 17 MiB witness-size budget rationale) [8](#0-7) .

### Likelihood Explanation
Reachable by any unprivileged account: an ordinary `FunctionCall` transaction that manipulates `output_data_receivers` after the size check, or returns a large value that becomes an oversized `DataReceipt`, is sufficient — confirmed reproducible by the repository's own regression tests, which document this as unfixed rather than hypothetical [9](#0-8) [10](#0-9) .

### Recommendation
Enforce `max_receipt_size` on receipts at every point a receipt can be mutated after its initial creation check (notably `output_data_receivers` attachment and value-return wrapping into `DataReceipt`), so that `ValidateReceiptMode::ExistingReceipt` never needs to tolerate oversized receipts. Until the root cause is fixed, ensure the "pretend it's `max_receipt_size`" clamping in `try_forward`/`generate_bandwidth_request` is applied consistently everywhere size is used for congestion accounting (not just admission), so real resource consumption cannot exceed what was granted.

### Proof of Concept
The repository's existing tests `test_max_receipt_size_promise_return` and `test_max_receipt_size_value_return` already construct and execute the attack path (deploy contract → call method that creates a receipt whose size is inflated above `max_receipt_size` after the creation-time check → assert the oversized receipt appears on-chain) [11](#0-10) .

### Citations

**File:** runtime/runtime/src/verifier.rs (L527-542)
```rust
pub(crate) fn validate_receipt(
    limit_config: &LimitConfig,
    receipt: &Receipt,
    current_protocol_version: ProtocolVersion,
    mode: ValidateReceiptMode,
) -> Result<(), ReceiptValidationError> {
    if mode == ValidateReceiptMode::NewReceipt {
        let receipt_size: u64 =
            borsh::object_length(receipt).unwrap().try_into().expect("Can't convert usize to u64");
        if receipt_size > limit_config.max_receipt_size {
            return Err(ReceiptValidationError::ReceiptSizeExceeded {
                size: receipt_size,
                limit: limit_config.max_receipt_size,
            });
        }
    }
```

**File:** runtime/runtime/src/verifier.rs (L573-586)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateReceiptMode {
    /// Used for validating new receipts that were just created.
    /// More strict than `OldReceipt` mode, which has to handle older receipts.
    NewReceipt,
    /// Used for validating older receipts that were saved in the state/received. Less strict than
    /// NewReceipt validation. Tolerates some receipts that wouldn't pass new validation. It has to
    /// be less strict because:
    /// 1) Older receipts might have been created before new validation rules.
    /// 2) There is a bug which allows to create receipts that are above the size limit. Runtime has
    ///    to handle them gracefully until the receipt size limit bug is fixed.
    ///    See https://github.com/near/nearcore/issues/12606 for details.
    ExistingReceipt,
}
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L124-267)
```rust
// A function call will generate a new receipt. Size of this receipt will be equal to
// `max_receipt_size`, it'll pass validation, but then `output_data_receivers` will be modified and
// the receipt's size will go above max_receipt_size. The receipt should be rejected, but currently
// isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
// Runtime shouldn't die when it encounters a receipt with size above `max_receipt_size`.
#[test]
fn test_max_receipt_size_promise_return() {
    init_test_logger();

    let account = create_account_id("account0");
    let account_signer = create_user_test_signer(&account);
    let mut env = TestLoopBuilder::new()
        .enable_rpc()
        .add_user_account(&account, Balance::from_near(10_000))
        .build();

    // Deploy the test contract
    let deploy_contract_tx = SignedTransaction::deploy_contract(
        101,
        &account,
        near_test_contracts::rs_contract().into(),
        &account_signer,
        env.rpc_node().head().last_block_hash,
    );
    env.rpc_runner().run_tx(deploy_contract_tx, Duration::seconds(5));

    // User calls a contract method
    // Contract method creates a DAG with two promises: [A -then-> B]
    // When promise A is executed, it creates a third promise - `C` and does a `promise_return`.
    // The DAG changes to: [C ->then-> B]
    // The receipt for promise C is a maximum size receipt.
    // Adding the `output_data_receivers` to C's receipt makes it go over the size limit.
    let base_receipt_template = Receipt::V0(ReceiptV0 {
        predecessor_id: account.clone(),
        receiver_id: account.clone(),
        receipt_id: CryptoHash::default(),
        receipt: ReceiptEnum::Action(ActionReceipt {
            signer_id: account.clone(),
            signer_public_key: account_signer.public_key().into(),
            gas_price: Balance::ZERO,
            output_data_receivers: vec![],
            input_data_ids: vec![],
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "noop".into(),
                args: vec![],
                gas: Gas::ZERO,
                deposit: Balance::ZERO,
            }))],
        }),
    });
    let base_receipt_template = action_receipt_v1_to_latest(&base_receipt_template);
    let base_receipt_size = borsh::object_length(&base_receipt_template).unwrap();
    let max_receipt_size = 4_194_304;
    let args_size = max_receipt_size - base_receipt_size;

    // Call the contract
    let large_receipt_tx = SignedTransaction::call(
        102,
        account.clone(),
        account.clone(),
        &account_signer,
        Balance::ZERO,
        "max_receipt_size_promise_return_method1".into(),
        format!("{{\"args_size\": {}}}", args_size).into(),
        Gas::from_teragas(300),
        env.rpc_node().head().last_block_hash,
    );
    env.rpc_runner().run_tx(large_receipt_tx, Duration::seconds(5));

    // Make sure that the last promise in the DAG was called
    let assert_test_completed = SignedTransaction::call(
        103,
        account.clone(),
        account,
        &account_signer,
        Balance::ZERO,
        "assert_test_completed".into(),
        "".into(),
        Gas::from_teragas(300),
        env.rpc_node().head().last_block_hash,
    );
    env.rpc_runner().run_tx(assert_test_completed, Duration::seconds(5));

    assert_oversized_receipt_occurred(&env.validator());
}

/// Return a value that is as large as max_receipt_size. The value will be wrapped in a data receipt
/// and the data receipt will be bigger than max_receipt_size. The receipt should be rejected, but
/// currently isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
/// Creates the following promise DAG:
/// A[self.return_large_value()] -then-> B[self.mark_test_completed()]
#[test]
fn test_max_receipt_size_value_return() {
    init_test_logger();

    let account = create_account_id("account0");
    let account_signer = create_user_test_signer(&account);
    let mut env = TestLoopBuilder::new()
        .enable_rpc()
        .add_user_account(&account, Balance::from_near(10_000))
        .build();

    // Deploy the test contract
    let deploy_contract_tx = SignedTransaction::deploy_contract(
        101,
        &account,
        near_test_contracts::rs_contract().into(),
        &account_signer,
        env.rpc_node().head().last_block_hash,
    );
    env.rpc_runner().run_tx(deploy_contract_tx, Duration::seconds(5));

    let max_receipt_size = 4_194_304;

    // Call the contract
    let large_receipt_tx = SignedTransaction::call(
        102,
        account.clone(),
        account.clone(),
        &account_signer,
        Balance::ZERO,
        "max_receipt_size_value_return_method".into(),
        format!("{{\"value_size\": {}}}", max_receipt_size).into(),
        Gas::from_teragas(300),
        env.rpc_node().head().last_block_hash,
    );
    env.rpc_runner().run_tx(large_receipt_tx, Duration::seconds(5));

    // Make sure that the last promise in the DAG was called
    let assert_test_completed = SignedTransaction::call(
        103,
        account.clone(),
        account,
        &account_signer,
        Balance::ZERO,
        "assert_test_completed".into(),
        "".into(),
        Gas::from_teragas(300),
        env.rpc_node().head().last_block_hash,
    );
    env.rpc_runner().run_tx(assert_test_completed, Duration::seconds(5));

    assert_oversized_receipt_occurred(&env.validator());
}
```

**File:** runtime/runtime/src/congestion_control.rs (L357-395)
```rust
            match Self::try_forward(
                receipt,
                gas,
                size,
                target_shard_id,
                &mut self.outgoing_limit,
                &mut self.outgoing_receipts,
                apply_state,
                &mut self.stats,
            )? {
                ReceiptForwarding::Forwarded => {
                    self.own_congestion_info.remove_receipt_bytes(size)?;
                    self.own_congestion_info.remove_buffered_receipt_gas(gas.as_gas().into())?;
                    if should_update_outgoing_metadatas {
                        // Can't update metadatas immediately because state_update is borrowed by iterator.
                        outgoing_metadatas_updates.push((ByteSize::b(size), gas));
                    }
                    // count how many to release later to avoid modifying
                    // `state_update` while iterating based on
                    // `state_update.trie`.
                    num_forwarded += 1;
                }
                ReceiptForwarding::NotForwarded(_) => {
                    break;
                }
            }
        }

        self.outgoing_buffers.to_shard(buffer_shard_id).pop_n(state_update, num_forwarded)?;
        for (size, gas) in outgoing_metadatas_updates {
            self.outgoing_metadatas.update_on_receipt_popped(
                buffer_shard_id,
                size,
                gas,
                state_update,
            )?;
        }
        Ok(())
    }
```

**File:** runtime/runtime/src/congestion_control.rs (L403-463)
```rust
    fn try_forward(
        receipt: Receipt,
        gas: Gas,
        mut size: u64,
        shard: ShardId,
        outgoing_limit: &mut HashMap<ShardId, OutgoingLimit>,
        outgoing_receipts: &mut Vec<Receipt>,
        apply_state: &ApplyState,
        stats: &mut ReceiptSinkStats,
    ) -> Result<ReceiptForwarding, RuntimeError> {
        // There is a bug which allows to create receipts that are above the size limit. Receipts
        // above the size limit might not fit under the maximum outgoing size limit. Let's pretend
        // that all receipts are at most `max_receipt_size` to avoid receipts getting stuck.
        // See https://github.com/near/nearcore/issues/12606
        let max_receipt_size = apply_state.config.wasm_config.limit_config.max_receipt_size;
        if size > max_receipt_size {
            tracing::debug!(
                target: "runtime",
                receipt_id=?receipt.receipt_id(),
                size,
                max_receipt_size,
                "try_forward observed a receipt with size exceeding the size limit",
            );
            size = max_receipt_size;
        }

        // Default case set to `Gas::MAX`: If no outgoing limit was defined for the receiving
        // shard, this usually just means the feature is not enabled. Or, it
        // could be a special case during resharding events. Or even a bug. In
        // any case, if we cannot know a limit, treating it as literally "no
        // limit" is the safest approach to ensure availability.
        let default_gas_limit = Gas::MAX;

        // Since bandwidth scheduler, a shard is not allowed to send any receipts if it doesn't have a grant.
        let default_size_limit = 0;

        let default_outgoing_limit =
            OutgoingLimit { gas: default_gas_limit, size: default_size_limit };
        let forward_limit = outgoing_limit.entry(shard).or_insert(default_outgoing_limit);

        let admission_gas = if ProtocolFeature::ClampOutgoingGasAdmission
            .enabled(apply_state.current_protocol_version)
        {
            gas.min(apply_state.config.congestion_control_config.allowed_shard_outgoing_gas)
        } else {
            gas
        };

        if forward_limit.gas >= admission_gas && forward_limit.size >= size {
            tracing::trace!(target: "runtime", ?shard, receipt_id=?receipt.receipt_id(), "forwarding buffered receipt");
            outgoing_receipts.push(receipt);
            forward_limit.gas = forward_limit.gas.saturating_sub(gas);
            forward_limit.size -= size;
            stats.forwarded_receipts.entry(shard).or_default().add_receipt(size, gas);

            Ok(ReceiptForwarding::Forwarded)
        } else {
            tracing::trace!(target: "runtime", ?shard, receipt_id=?receipt.receipt_id(), "not forwarding buffered receipt");
            Ok(ReceiptForwarding::NotForwarded(receipt))
        }
    }
```

**File:** runtime/runtime/src/congestion_control.rs (L556-566)
```rust
        // There's a bug which allows to create receipts above `max_receipt_size` (https://github.com/near/nearcore/issues/12606).
        // This could cause problems with bandwidth scheduler which would generate requests for size above max size, and these
        // requests would never be fulfilled. For bandwidth requests let's pretend that all sizes are below `max_receipt_size`.
        // The same pretending logic is also present in `try_forward` which compares receipt size with outgoing limit.
        // This logic should also make it possible to do protocol upgrades that lower `max_receipt_size` without too much trouble.
        let sizes_iter = receipt_sizes_iter
            .map_ok(|group_size| std::cmp::min(group_size, params.max_receipt_size));

        // Create the bandwidth request based on buffered receipt (group) sizes
        BandwidthRequest::make_from_receipt_sizes(to_shard, sizes_iter, params)
    }
```

**File:** docs/misc/state_witness_size_limits.md (L1-18)
```markdown
## State witness size limits

Some limits were introduced to keep the size of `ChunkStateWitness` reasonable.
`ChunkStateWitness` contains all the incoming transactions and receipts that will be processed during chunk application and in theory a single receipt could be tens of megabytes in size. Distributing a `ChunkStateWitness` this large would be troublesome, so we limit the size and number of transactions, receipts, etc. The limits aim to keep the total uncompressed size of `ChunkStateWitness` under 17MiB.

There are two types of size limits:

* Hard limit - the size must be below this limit, anything else is considered invalid
* Soft limit - things are added until the limit is exceeded, after that things stop being added. The last added thing is allowed to slightly exceed the limit.

The limits are:

* `max_transaction_size = 1.5 MiB`
  * All transactions must be below 1.5 MiB, otherwise they'll be considered invalid and rejected.
  * Previously was 4MiB, now reduced to 1.5MiB
* `max_receipt_size - 4 MiB`:
  * All receipts must be below 4 MiB, otherwise they'll be considered invalid and rejected.
  * Previously there was no limit on receipt size. Set to 4MiB, might be reduced to 1.5MiB in the future to match the transaction limit.
```
