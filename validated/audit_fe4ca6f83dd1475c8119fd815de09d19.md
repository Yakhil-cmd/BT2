No vulnerability found for this question.

Investigation notes: This repository is a Substrate/Polkadot Rust runtime codebase, not a Solidity AMM/DEX contract, so the `priceALast`/`priceBLast` raw integer-division pattern from `FPair.sol` has no direct code structure to map onto. The closest analog searches turned up price/rate/ratio conversion logic such as `relay_era_payout` [1](#0-0)  and the cross-chain fee conversion helpers `convert_from_udot_to_uksm`/`convert_from_uksm_to_udot` [2](#0-1) [3](#0-2) , as well as the Asset Hub `EraPayout` inflation curve [4](#0-3) .

All of these consistently use `FixedU128`/`Perquintill`/`Perbill` fixed-point arithmetic types (`from_rational`, `saturating_mul`, `into_inner()/DIV`) rather than performing raw integer division directly on unscaled balance values as `FPair.sol` does. This is precisely the mitigation pattern recommended in the external report, already applied throughout this codebase. There is no reachable, attacker-controlled entry point that truncates a price/ratio via naive integer division on raw reserves/balances in the way described in the report, so the disqualification criteria ("theoretical-only issue with no protocol impact" / "no reachable attacker-controlled entry path") apply.

### Citations

**File:** relay/common/src/lib.rs (L52-84)
```rust
pub fn relay_era_payout(params: EraPayoutParams) -> (Balance, Balance) {
	let EraPayoutParams {
		total_staked,
		total_stakable,
		ideal_stake,
		max_annual_inflation,
		min_annual_inflation,
		falloff,
		period_fraction,
		legacy_auction_proportion,
	} = params;

	let delta_annual_inflation = max_annual_inflation.saturating_sub(min_annual_inflation);

	let ideal_stake = ideal_stake.saturating_sub(legacy_auction_proportion.unwrap_or_default());

	let stake = Perquintill::from_rational(total_staked, total_stakable);
	let adjustment = pallet_staking_reward_fn::compute_inflation(stake, ideal_stake, falloff);
	let staking_inflation =
		min_annual_inflation.saturating_add(delta_annual_inflation * adjustment);

	let max_payout = period_fraction * max_annual_inflation * total_stakable;
	let staking_payout = (period_fraction * staking_inflation) * total_stakable;
	let rest = max_payout.saturating_sub(staking_payout);

	let other_issuance = total_stakable.saturating_sub(total_staked);
	if total_staked > other_issuance {
		let _cap_rest = Perquintill::from_rational(other_issuance, total_staked) * staking_payout;
		// We don't do anything with this, but if we wanted to, we could introduce a cap on the
		// treasury amount with: `rest = rest.min(cap_rest);`
	}
	(staking_payout, rest)
}
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/primitives/src/lib.rs (L162-176)
```rust
fn convert_from_udot_to_uksm(price_in_udot: Balance) -> Balance {
	// assuming exchange rate is 5 DOTs for 1 KSM
	let ksm_to_dot_economic_rate = FixedU128::from_rational(1, 5);
	// tokens have different nominals and we need to take that into account
	let nominal_ratio = FixedU128::from_rational(
		kusama_runtime_constants::currency::UNITS,
		polkadot_runtime_constants::currency::UNITS,
	);

	ksm_to_dot_economic_rate
		.saturating_mul(nominal_ratio)
		.saturating_mul(FixedU128::saturating_from_integer(price_in_udot))
		.into_inner() /
		FixedU128::DIV
}
```

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/primitives/src/lib.rs (L153-167)
```rust
fn convert_from_uksm_to_udot(price_in_uksm: Balance) -> Balance {
	// assuming exchange rate is 5 DOTs for 1 KSM
	let dot_to_ksm_economic_rate = FixedU128::from_rational(5, 1);
	// tokens have different nominals and we need to take that into account
	let nominal_ratio = FixedU128::from_rational(
		polkadot_runtime_constants::currency::UNITS,
		kusama_runtime_constants::currency::UNITS,
	);

	dot_to_ksm_economic_rate
		.saturating_mul(nominal_ratio)
		.saturating_mul(FixedU128::saturating_from_integer(price_in_uksm))
		.into_inner() /
		FixedU128::DIV
}
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/staking/mod.rs (L344-375)
```rust
	fn yearly_after_hard_cap(relay_block_num: BlockNumber) -> Balance {
		let march_14_2026_ti = FixedU128::saturating_from_integer(Self::MARCH_2026_TI);
		let target_ti = FixedU128::saturating_from_integer(Self::HARD_CAP_TARGET);

		// Start date of the curve is set two years prior, thus ensuring first step in March,
		// 2026.
		let two_years_before_march =
			FixedU128::saturating_from_integer(Self::HARD_CAP_START - (2 * RC_YEARS));
		let relay_block_fp = FixedU128::saturating_from_integer(relay_block_num);
		let step_duration = FixedU128::saturating_from_integer(2 * RC_YEARS);

		let two_year_rate = Self::BI_ANNUAL_RATE;

		let Ok(ti_curve) = SteppedCurve::try_new(
			// The start date of the curve.
			two_years_before_march,
			// The initial value of the curve.
			march_14_2026_ti,
			// Target TI.
			RemainingPct { target: target_ti, pct: two_year_rate },
			// Step every two years.
			step_duration,
		) else {
			return 0
		};

		// The last step size tells us the expected TI increase over the current two year
		// period.
		let two_year_emission_fp = ti_curve.last_step_size(relay_block_fp);
		let two_year_emission: u128 = two_year_emission_fp.into_inner() / FixedU128::DIV;
		FixedU128::from_rational(1, 2).saturating_mul_int(two_year_emission)
	}
```
