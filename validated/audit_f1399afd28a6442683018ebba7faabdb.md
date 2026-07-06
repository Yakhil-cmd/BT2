### Title
Precision Loss in Per-Epoch Reward Calculation Due to Intermediate Integer Division in `epochs_in_year` - (File: src/reward_supplier/reward_supplier.cairo)

### Summary
`calculate_current_epoch_rewards` in `RewardSupplier` computes per-epoch rewards by first computing `epochs_in_year = SECONDS_IN_YEAR / epoch_duration` (integer division, truncating down), then dividing `yearly_mint / epochs_in_year`. Because the intermediate division truncates `epochs_in_year` to a smaller integer, the divisor used in the second step is smaller than the true value, causing per-epoch rewards to be systematically inflated relative to what the minting curve formula intends.

### Finding Description
The root cause is a two-step integer division chain that is mathematically equivalent to the correct formula only when `SECONDS_IN_YEAR` is exactly divisible by `epoch_duration`. In all other cases, the truncation in step 1 inflates the result of step 2.

**Step 1 — `epochs_in_year()` in `src/staking/objects.cairo`:** [1](#0-0) 

```cairo
fn epochs_in_year(self: @EpochInfo) -> u64 {
    SECONDS_IN_YEAR / (*epoch_duration).into()   // ← integer division truncates DOWN
}
```

**Step 2 — `calculate_current_epoch_rewards` in `src/reward_supplier/reward_supplier.cairo`:** [2](#0-1) 

```cairo
let yearly_mint = minting_curve_dispatcher.yearly_mint();
let epochs_in_year = staking_dispatcher.get_epoch_info().epochs_in_year();
let total_rewards = yearly_mint / epochs_in_year.into();   // ← divided by truncated value
```

The mathematically correct formula is:
```
total_rewards = yearly_mint * epoch_duration / SECONDS_IN_YEAR
```

Because `floor(SECONDS_IN_YEAR / epoch_duration) ≤ SECONDS_IN_YEAR / epoch_duration`, the actual divisor is smaller than the true value, so `total_rewards` is larger than intended.

This function is called from the production staking contract (2 call-sites in `src/staking/staking.cairo`) for V1/V2 (attestation-based) reward distribution. [3](#0-2) 

The V3 path (`update_current_epoch_block_rewards`) correctly avoids this by using `mul_wide_and_div` in a single fused operation: [4](#0-3) 

### Impact Explanation
Every epoch in V1/V2, stakers receive slightly more STRK than the minting curve formula intends. The excess accumulates over every epoch for the lifetime of the V1/V2 protocol phase. This constitutes systematic over-minting beyond the intended inflation schedule — a form of protocol insolvency — and is a direct analog of the external report's "wrong value for price ratio" class: an intermediate integer division produces a truncated intermediate that is then used as a divisor, yielding a result that diverges from the mathematically correct value.

### Likelihood Explanation
The condition `SECONDS_IN_YEAR % epoch_duration == 0` is almost never satisfied in practice. `SECONDS_IN_YEAR = 31,536,000`. A 7-day epoch (`epoch_duration = 604,800`) gives `31,536,000 / 604,800 = 52.142857…`, truncated to `52`. The per-epoch reward is `yearly_mint / 52` instead of the correct `yearly_mint / 52.142857…`. The excess per year is approximately `0.274%` of `yearly_mint`. For a yearly mint of 100 M STRK, this is ~274 K STRK of excess minting per year. The bug fires on every single epoch transition.

### Recommendation
Replace the two-step division with a single fused multiply-then-divide, mirroring the pattern already used in `update_current_epoch_block_rewards`:

```cairo
// Instead of:
let epochs_in_year = staking_dispatcher.get_epoch_info().epochs_in_year();
let total_rewards = yearly_mint / epochs_in_year.into();

// Use:
let epoch_duration = staking_dispatcher.get_epoch_info().epoch_duration(); // expose getter
let total_rewards = mul_wide_and_div(
    lhs: yearly_mint,
    rhs: epoch_duration.into(),
    div: SECONDS_IN_YEAR.into(),
).expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW);
```

This eliminates the intermediate truncation and matches the precision of the V3 block-reward path.

### Proof of Concept
Concrete numeric example with `epoch_duration = 604,800` s (7 days), `yearly_mint = 100_000_000 * 10^18`:

| Formula | Value |
|---|---|
| `epochs_in_year` (truncated) | `52` |
| `total_rewards` (current) | `yearly_mint / 52 = 1,923,076,923,076,923,076,923,076` |
| `total_rewards` (correct) | `yearly_mint * 604800 / 31536000 = 1,917,808,219,178,082,191,780,821` |
| Excess per epoch | `5,268,703,898,840,885,142,255` (~0.274%) |
| Excess per year (×52 epochs) | `~274,052,602,739,726,027,397,260` STRK-wei |

The same pattern is visible in the test utility `_calculate_current_epoch_rewards_v1`: [5](#0-4) 

which mirrors the production code and confirms the two-step division is the intended (but imprecise) implementation path for V1/V2.

### Citations

**File:** src/staking/objects.cairo (L214-221)
```text
    fn epochs_in_year(self: @EpochInfo) -> u64 {
        let epoch_duration = if self.update_done_in_this_epoch() {
            self.previous_epoch_duration
        } else {
            self.epoch_duration
        };
        SECONDS_IN_YEAR / (*epoch_duration).into()
    }
```

**File:** src/reward_supplier/reward_supplier.cairo (L150-163)
```text
        fn calculate_current_epoch_rewards(self: @ContractState) -> (Amount, Amount) {
            let minting_curve_dispatcher = self.minting_curve_dispatcher.read();
            let staking_dispatcher = IStakingDispatcher {
                contract_address: self.staking_contract.read(),
            };

            let yearly_mint = minting_curve_dispatcher.yearly_mint();
            let epochs_in_year = staking_dispatcher.get_epoch_info().epochs_in_year();
            let total_rewards = yearly_mint / epochs_in_year.into();
            let btc_rewards = calculate_btc_rewards(:total_rewards);
            let strk_rewards = total_rewards - btc_rewards;

            (strk_rewards, btc_rewards)
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L178-183)
```text
            let total_rewards = mul_wide_and_div(
                lhs: yearly_mint,
                rhs: avg_block_duration.into(),
                div: BLOCK_DURATION_SCALE.into() * SECONDS_IN_YEAR.into(),
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW);
```

**File:** src/test_utils.cairo (L1028-1031)
```text
    let yearly_mint = minting_curve_dispatcher.yearly_mint();
    let epochs_in_year = staking_dispatcher.get_epoch_info().epochs_in_year();
    let total_rewards = yearly_mint / epochs_in_year.into();
    total_rewards
```
