### Title
Snowbridge outbound queue commits messages using `PricingParameters` fetched at *dequeue* time, not the parameters the user paid for at *send* time - ([File: bridges/snowbridge/pallets/outbound-queue/src/lib.rs])

### Summary
This is a structural analog of the Taiko `LibDepositing.processDeposits` finding: a user-facing "submit now, process later" pipeline capped at a fixed number of items per block, where the value/fee actually charged to the user at submission time can diverge from the value used when the request is finally processed, with no check reconciling the two. In Snowbridge's outbound queue this manifests as the fee/gas-price parameters embedded into the committed Ethereum message being re-read fresh at `do_process_message` time rather than being pinned to whatever `PricingParameters` were used to charge the sender when the message was validated/enqueued.

### Finding Description
`Pallet::do_process_message` in `bridges/snowbridge/pallets/outbound-queue/src/lib.rs` is the analog of Taiko's `LibDepositing.processDeposits`: it is called by the generic `MessageQueue` pallet to drain queued outbound messages, but is explicitly rate-limited per block: [1](#0-0) 

This mirrors the Taiko `ethDepositMaxCountPerBlock` cap (32 deposits/block) — here it is `T::MaxMessagesPerBlock` (32 in the Bridge Hub Westend runtime), and the pallet's own tests demonstrate a multi-block backlog forming under load: [2](#0-1) 

When a queued message finally gets its turn (potentially several blocks after it was originally validated and paid for), the pallet does **not** reuse the pricing that was in effect (and charged to the user) at send time. Instead it re-fetches the *current* pricing parameters and bakes them into the immutable, committed message that determines the relayer's gas-price ceiling and reward on the Ethereum side: [3](#0-2) 

The fee charged to the sender, by contrast, is computed via `calculate_fee` using whatever `PricingParameters` are supplied to it (documented as reflecting the ETH/DOT exchange rate and gas price at calculation time): [4](#0-3) [5](#0-4) 

Because message validation/fee-charging happens at `send`/`deliver` time (when the ticket is created and the user is charged) while `max_fee_per_gas`/`reward` used for actual on-chain settlement is computed later at `do_process_message` (dequeue) time, there is a time-of-charge vs. time-of-commit gap analogous to Taiko's deposit-vs-process gap, during which `T::PricingParameters` (an oracle-like value, adjustable by governance/`EthereumSystem`) can change. There is no check in `do_process_message` that the currently-fetched pricing parameters are consistent with (or bounded by) whatever was charged to the user when the message was originally accepted, i.e. no "slippage" check comparable to `amount_out_min`/`amount_in_max` used elsewhere in this codebase (e.g. `substrate/frame/asset-conversion/src/lib.rs` swap functions, which do enforce exactly this kind of check).

### Impact Explanation
If `PricingParameters` move upward between the time a message is enqueued/paid-for and the time it is actually processed (due to queue congestion capped by `MaxMessagesPerBlock`, exactly as demonstrated in the pallet's own congestion tests), the fee the sender already paid may not match the `max_fee_per_gas`/reward baked into the finally-committed message. This can under-fund message delivery/execution incentives on the Ethereum side relative to real gas conditions at commit time, or conversely commit a stale, since-reduced fee ceiling that no longer reflects what the user actually paid — a mismatch between promised and delivered value with no user-controlled bound, similar in class (though not necessarily in magnitude) to the acknowledged Taiko Medium finding.

### Likelihood Explanation
Queue congestion causing multi-block delays before processing is explicitly demonstrated in the codebase's own tests (`governance_message_does_not_get_the_chance_to_processed_in_same_block_when_congest_of_low_priority_sibling_messages`), so the "delay window" precondition is realistic and requires no privileged actor — any user can submit enough low-priority messages (or simply be queued behind others) to create the gap. However, I was not able to fully verify, within available tool calls, the exact code path in `send_message_impl.rs` that charges the user (i.e., whether the fee is withdrawn immediately using the same `PricingParameters` later re-read in `do_process_message`, or whether some other reconciliation exists downstream, e.g. in `submit_delivery_receipt`/reward settlement). This is an open verification gap.

### Recommendation
Pin the pricing parameters (or at minimum the `max_fee_per_gas`/reward values) used to charge the sender at `validate`/`deliver` time into the enqueued message payload, and reuse those pinned values in `do_process_message` rather than re-reading `T::PricingParameters::get()` at dequeue time. Alternatively, add an explicit reconciliation/slippage check that rejects or refunds when currently-fetched pricing diverges materially from what was charged at send time — analogous to the `amount_out_min`/`amount_in_max` pattern already used in `pallet-asset-conversion`.

### Proof of Concept
**Execution status: not executed.** I do not have terminal/test-execution capability in this session (ask-only mode), so no integration test was run against this repository. The finding above is based on static code reading of `bridges/snowbridge/pallets/outbound-queue/src/lib.rs` and its test module; I could not fully trace `send_message_impl.rs`'s exact fee-withdrawal timing or confirm whether a downstream reconciliation step (e.g., during `submit_delivery_receipt` reward payout) neutralizes this gap. A background Devin session with repository/test access would be needed to (a) confirm the exact fee-charging code path at send/validate time, (b) write a FRAME integration test that enqueues a message, artificially advances `PricingParameters` via governance/`EthereumSystem` between enqueue and multi-block-delayed processing, and (c) assert whether the committed `max_fee_per_gas`/`reward` diverges from what the sender was charged, with a concrete measurable loss. Given this verification gap, treat this as a candidate structural analog requiring further confirmation rather than a fully proven vulnerability.

### Citations

**File:** bridges/snowbridge/pallets/outbound-queue/src/lib.rs (L57-70)
```rust
//! This is an interim measure. Once ETH/DOT liquidity pools are available in the Polkadot network,
//! we'll use them as a source of pricing info, subject to certain safeguards.
//!
//! ## Fee Computation Function
//!
//! ```text
//! LocalFee(Message) = WeightToFee(ProcessMessageWeight(Message))
//! RemoteFee(Message) = MaxGasRequired(Message) * Params.MaxFeePerGas + Params.Reward
//! RemoteFeeAdjusted(Message) = Params.Multiplier * (RemoteFee(Message) / Params.Ratio("ETH/DOT"))
//! Fee(Message) = LocalFee(Message) + RemoteFeeAdjusted(Message)
//! ```
//!
//! By design, the computed fee includes a safety factor (the `Multiplier`) to cover
//! unfavourable fluctuations in the ETH/DOT exchange rate.
```

**File:** bridges/snowbridge/pallets/outbound-queue/src/lib.rs (L307-313)
```rust
			// Yield if the maximum number of messages has been processed this block.
			// This ensures that the weight of `on_finalize` has a known maximum bound.
			ensure!(
				MessageLeaves::<T>::decode_len().unwrap_or(0) <
					T::MaxMessagesPerBlock::get() as usize,
				Yield
			);
```

**File:** bridges/snowbridge/pallets/outbound-queue/src/lib.rs (L332-352)
```rust
			let pricing_params = T::PricingParameters::get();
			let command = queued_message.command.index();
			let params = queued_message.command.abi_encode();
			let max_dispatch_gas =
				T::GasMeter::maximum_dispatch_gas_used_at_most(&queued_message.command);
			let reward = pricing_params.rewards.remote;

			// Construct the final committed message
			let message = CommittedMessage {
				channel_id: queued_message.channel_id,
				nonce,
				command,
				params,
				max_dispatch_gas,
				max_fee_per_gas: pricing_params
					.fee_per_gas
					.try_into()
					.defensive_unwrap_or(u128::MAX),
				reward: reward.try_into().defensive_unwrap_or(u128::MAX),
				id: queued_message.id,
			};
```

**File:** bridges/snowbridge/pallets/outbound-queue/src/lib.rs (L366-393)
```rust
		/// Calculate total fee in native currency to cover all costs of delivering a message to the
		/// remote destination. See module-level documentation for more details.
		pub(crate) fn calculate_fee(
			gas_used_at_most: u64,
			params: PricingParameters<T::Balance>,
		) -> Fee<T::Balance> {
			// Remote fee in ether
			let fee = Self::calculate_remote_fee(
				gas_used_at_most,
				params.fee_per_gas,
				params.rewards.remote,
			);

			// downcast to u128
			let fee: u128 = fee.try_into().defensive_unwrap_or(u128::MAX);

			// multiply by multiplier and convert to local currency
			let fee = FixedU128::from_inner(fee)
				.saturating_mul(params.multiplier)
				.checked_div(&params.exchange_rate)
				.expect("exchange rate is not zero; qed")
				.into_inner();

			// adjust fixed point to match local currency
			let fee = Self::convert_from_ether_decimals(fee);

			Fee::from((Self::calculate_local_fee(), fee))
		}
```

**File:** bridges/snowbridge/pallets/outbound-queue/src/test.rs (L169-226)
```rust
#[test]
fn governance_message_does_not_get_the_chance_to_processed_in_same_block_when_congest_of_low_priority_sibling_messages(
) {
	use snowbridge_core::PRIMARY_GOVERNANCE_CHANNEL;
	use AggregateMessageOrigin::*;

	let sibling_id: u32 = 1000;
	let sibling_channel_id: ChannelId = ParaId::from(sibling_id).into();

	new_tester().execute_with(|| {
		// submit a lot of low priority messages from asset_hub which will need multiple blocks to
		// execute(20 messages for each block so 40 required at least 2 blocks)
		let max_messages = 40;
		for _ in 0..max_messages {
			// submit low priority message
			let message = mock_message(sibling_id);
			let (ticket, _) = OutboundQueue::validate(&message).unwrap();
			OutboundQueue::deliver(ticket).unwrap();
		}

		let footprint = MessageQueue::footprint(Snowbridge(sibling_channel_id));
		assert_eq!(footprint.storage.count, (max_messages) as u64);

		let message = mock_governance_message::<Test>();
		let (ticket, _) = OutboundQueue::validate(&message).unwrap();
		OutboundQueue::deliver(ticket).unwrap();

		// move to next block
		ServiceWeight::set(Some(Weight::MAX));
		run_to_end_of_next_block();

		// first process 20 messages from sibling channel
		let footprint = MessageQueue::footprint(Snowbridge(sibling_channel_id));
		assert_eq!(footprint.storage.count, 40 - 20);

		// and governance message does not have the chance to execute in same block
		let footprint = MessageQueue::footprint(Snowbridge(PRIMARY_GOVERNANCE_CHANNEL));
		assert_eq!(footprint.storage.count, 1);

		// move to next block
		ServiceWeight::set(Some(Weight::MAX));
		run_to_end_of_next_block();

		// now governance message get executed in this block
		let footprint = MessageQueue::footprint(Snowbridge(PRIMARY_GOVERNANCE_CHANNEL));
		assert_eq!(footprint.storage.count, 0);

		// and this time process 19 messages from sibling channel so we have 1 message left
		let footprint = MessageQueue::footprint(Snowbridge(sibling_channel_id));
		assert_eq!(footprint.storage.count, 1);

		// move to the next block, the last 1 message from sibling channel get executed
		ServiceWeight::set(Some(Weight::MAX));
		run_to_end_of_next_block();
		let footprint = MessageQueue::footprint(Snowbridge(sibling_channel_id));
		assert_eq!(footprint.storage.count, 0);
	});
}
```
