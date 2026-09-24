## Analog Found

### Title
`OutboundQueue::calculate_fee()` truncates a non-zero remote fee to zero via decimal-scaling division, letting messages be charged nothing for a promised relayer reward - ([File: bridges/snowbridge/pallets/outbound-queue/src/lib.rs])

### Summary
The Hubble report shows `getUnderlyingPrice()` performing `answer /= 100` without checking that the pre-division value exceeds the divisor, so a valid positive price truncates to `0` and corrupts a downstream calculation (`InsuranceFund.startAuction()`'s `currentPrice`). The Snowbridge `outbound-queue` pallet's `calculate_fee()` has the exact same defect class: it converts a wei-denominated remote fee into native-currency units via `convert_from_ether_decimals()`, an unchecked integer division by `10^decimals` (`10^8` for a 10-decimal chain), with no check that the dividend exceeds the divisor. When it doesn't, the "remote fee" charged to the message sender silently becomes `0`, even though `PricingParameters::validate()` guarantees every input parameter (`fee_per_gas`, `rewards.remote`, `multiplier`, `exchange_rate`) is non-zero.

### Finding Description
`calculate_fee` computes the fee a user must pay upfront for having a message relayed to Ethereum: [1](#0-0) 

The final downcast step performs the truncating division: [2](#0-1) 

`ETHER_DECIMALS` is `18` and `T::Decimals::get()` is constrained to `10` or `12` by `integrity_test`, so `decimals` is `8` or `6` and `denom` is `10^8` or `10^6`: [3](#0-2) 

`PricingParameters::validate()` only checks that each individual field is non-zero — it never checks that the *computed* remote fee after decimal conversion remains non-zero: [4](#0-3) 

This fee is produced from `calculate_fee` and returned to `SendMessage::validate`, the real, reachable entry point invoked whenever any ordinary user's XCM message is exported to Ethereum (e.g. an asset transfer) or the system pallet sends a command — no privileged role is required: [5](#0-4) 

Critically, the reward promised to Ethereum-side relayers and committed into the outbound message is taken directly from `pricing_params.rewards.remote` in wei, **independent of** the truncated `fee.remote` collected from the sender: [6](#0-5) 

So the invariant that "the fee charged to the sender covers the reward promised to relayers" (documented in the module's Fee Computation Function) is broken by unchecked integer division exactly as in the reported analog: a valid, non-zero, pre-division amount can be smaller than the scaling denominator and become `0`.

### Impact Explanation
When the computed `fee.remote` rounds to zero, users obtain bridge message delivery (with a real, non-zero relayer reward committed into the message and payable on the Ethereum side) while being charged nothing for that component of the fee. This breaks the fee-integrity invariant documented in the pallet ("An upfront fee must be paid for delivering a message... covers... the gas refund paid out to relayers... an additional reward paid out to relayers"), causing under-collection relative to the promised payout — a fee-accounting/integrity defect, matching the Medium classification of the original report (an invalid computed value silently propagating as zero rather than reverting or reflecting the true, non-zero cost).

### Likelihood Explanation
Reachable by any unprivileged user who triggers an outbound message (e.g., any XCM asset transfer routed to Ethereum) as long as governance-set `PricingParameters` (native decimals `10`/`12` vs Ether's `18` decimals) put the post-multiplier/division value below the `10^8`/`10^6` denominator — plausible for small message gas costs, low `fee_per_gas`, or low ETH/DOT `exchange_rate` regimes, none of which are excluded by `PricingParameters::validate()`. The maintainers' own test comment acknowledges the outcome is "invalid" and "should be avoided," confirming this is a recognized, unguarded gap rather than a designed behavior.

### Recommendation
In `convert_from_ether_decimals` (and/or `calculate_fee`), reject or round up when the truncating division would yield `0` for a non-zero dividend (mirroring the fix already applied elsewhere in this codebase, e.g. `pallet-asset-conversion`'s hardening against zero-rounding outputs, and `pallet-psm`'s `AmountTooSmallAfterConversion`/round-trip handling). At minimum, enforce a floor of `1` unit (or reject processing) when `fee > 0` but `fee / denom == 0`, so the charged fee can never be strictly less than the module's documented fee-computation guarantee.

### Proof of Concept
An existing, unmocked unit test in the pallet's own test harness directly reproduces the truncation through the real `calculate_fee` function with fully valid, non-zero `PricingParameters` (passing `validate()`): [7](#0-6) 

Execution result (from the repository's own test, `test_calculate_fees_with_valid_exchange_rate_but_remote_fee_calculated_as_zero`): with `gas_used = 250000`, `fee_per_gas = 1`, `rewards.remote = 1`, `exchange_rate = 1/1`, `multiplier = 1/1` — all individually non-zero and passing `PricingParameters::validate()` — the assertion `fee.remote == 0` holds, confirming the guard-free truncation. The test's own comment states: "Though none zero pricing params the remote fee calculated here is invalid which should be avoided," i.e., the maintainers have already identified but not fixed this rounding-to-zero defect. No mocked authority or proof acceptance was used; this exercises the production `calculate_fee`/`convert_from_ether_decimals` code path directly.

### Citations

**File:** bridges/snowbridge/pallets/outbound-queue/src/lib.rs (L259-262)
```rust
		fn integrity_test() {
			let decimals = T::Decimals::get();
			assert!(decimals == 10 || decimals == 12, "Decimals should be 10 or 12");
		}
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

**File:** bridges/snowbridge/pallets/outbound-queue/src/lib.rs (L368-393)
```rust
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

**File:** bridges/snowbridge/pallets/outbound-queue/src/lib.rs (L411-418)
```rust
		// 1 DOT has 10 digits of precision
		// 1 KSM has 12 digits of precision
		// 1 ETH has 18 digits of precision
		pub(crate) fn convert_from_ether_decimals(value: u128) -> T::Balance {
			let decimals = ETHER_DECIMALS.saturating_sub(T::Decimals::get()) as u32;
			let denom = 10u128.saturating_pow(decimals);
			value.checked_div(denom).expect("divisor is non-zero; qed").into()
		}
```

**File:** bridges/snowbridge/primitives/core/src/pricing.rs (L39-56)
```rust
	pub fn validate(&self) -> Result<(), InvalidPricingParameters> {
		if self.exchange_rate == FixedU128::zero() {
			return Err(InvalidPricingParameters);
		}
		if self.fee_per_gas == U256::zero() {
			return Err(InvalidPricingParameters);
		}
		if self.rewards.local.is_zero() {
			return Err(InvalidPricingParameters);
		}
		if self.rewards.remote.is_zero() {
			return Err(InvalidPricingParameters);
		}
		if self.multiplier == FixedU128::zero() {
			return Err(InvalidPricingParameters);
		}
		Ok(())
	}
```

**File:** bridges/snowbridge/pallets/outbound-queue/src/send_message_impl.rs (L41-74)
```rust
	fn validate(
		message: &Message,
	) -> Result<(Self::Ticket, Fee<<Self as SendMessageFeeProvider>::Balance>), SendError> {
		// The inner payload should not be too large
		let payload = message.command.abi_encode();
		ensure!(
			payload.len() < T::MaxMessagePayloadSize::get() as usize,
			SendError::MessageTooLarge
		);

		// Ensure there is a registered channel we can transmit this message on
		ensure!(T::Channels::contains(&message.channel_id), SendError::InvalidChannel);

		// Generate a unique message id unless one is provided
		let message_id: H256 = message
			.id
			.unwrap_or_else(|| unique((message.channel_id, &message.command)).into());

		let gas_used_at_most = T::GasMeter::maximum_gas_used_at_most(&message.command);
		let fee = Self::calculate_fee(gas_used_at_most, T::PricingParameters::get());

		let queued_message: VersionedQueuedMessage = QueuedMessage {
			id: message_id,
			channel_id: message.channel_id,
			command: message.command.clone(),
		}
		.into();
		// The whole message should not be too large
		let encoded = queued_message.encode().try_into().map_err(|_| SendError::MessageTooLarge)?;

		let ticket = Ticket { message_id, channel_id: message.channel_id, message: encoded };

		Ok((ticket, fee))
	}
```

**File:** bridges/snowbridge/pallets/outbound-queue/src/test.rs (L303-319)
```rust
#[test]
fn test_calculate_fees_with_valid_exchange_rate_but_remote_fee_calculated_as_zero() {
	new_tester().execute_with(|| {
		let gas_used: u64 = 250000;
		let price_params: PricingParameters<<Test as Config>::Balance> = PricingParameters {
			exchange_rate: FixedU128::from_rational(1, 1),
			fee_per_gas: 1_u32.into(),
			rewards: Rewards { local: 1_u32.into(), remote: 1_u32.into() },
			multiplier: FixedU128::from_rational(1, 1),
		};
		let fee = OutboundQueue::calculate_fee(gas_used, price_params.clone());
		assert_eq!(fee.local, 698000000);
		// Though none zero pricing params the remote fee calculated here is invalid
		// which should be avoided
		assert_eq!(fee.remote, 0);
	});
}
```
