### Title
Block Duration Clamping Causes Incorrect Epoch Reward Calculation - (File: src/reward_supplier/reward_supplier.cairo)

### Summary
The `set_avg_block_duration` function in `RewardSupplier` silently clamps the measured block duration to a configured `[min_block_duration, max_block_duration]` band and writes the clamped value to storage. This clamped value is then used directly in `update_current_epoch_block_rewards` to compute per-epoch staking rewards. When actual Starknet block times fall outside the configured band, rewards are systematically over- or under-distributed for the entire epoch — an exact structural analog to the Chainlink `minAnswer/maxAnswer` circuit-breaker bug.

### Finding Description
In `src/reward_supplier/reward_supplier.cairo`, `set_avg_block_duration` (called at the start of every epoch from `update_current_epoch_block_rewards`) computes the real average block duration from on-chain timestamps and then unconditionally clamps it:

```cairo
// lines 369–380
let mut calculated_block_duration = mul_wide_and_div(
    lhs: time_delta, rhs: BLOCK_DURATION_SCALE, div: num_blocks,
)
    .expect_with_err(err: Error::BLOCK_DURATION_OVERFLOW);
// Adjust calculated_block_duration with min and max block duration.
let block_duration_config = self.block_duration_config.read();
calculated_block_duration = calculated_block_duration
    .clamp(
        block_duration_config.min_block_duration,
        block_duration_config.max_block_duration,
    );
self.avg_block_duration.write(calculated_block_duration);
``` [1](#0-0) 

The default band is `[min=200, max=500]` (i.e., 2 s – 5 s, in units of `1/BLOCK_DURATION_SCALE` seconds). [2](#0-1) 

The stored `avg_block_duration` is then consumed immediately in `update_current_epoch_block_rewards`:

```cairo
// lines 177–186
let avg_block_duration = self.avg_block_duration.read();
let total_rewards = mul_wide_and_div(
    lhs: yearly_mint,
    rhs: avg_block_duration.into(),
    div: BLOCK_DURATION_SCALE.into() * SECONDS_IN_YEAR.into(),
)
    .expect_with_err(InternalError::REWARDS_COMPUTATION_OVERFLOW);
let btc_rewards = calculate_btc_rewards(:total_rewards);
let strk_rewards = total_rewards - btc_rewards;
(strk_rewards, btc_rewards)
``` [3](#0-2) 

The formula is effectively:

```
total_rewards = yearly_mint × (avg_block_duration / BLOCK_DURATION_SCALE) / SECONDS_IN_YEAR
```

When the real block duration is outside `[2 s, 5 s]`, the clamped value — not the real value — drives the reward amount. No revert, no event, no flag is raised.

### Impact Explanation

**Case A — blocks faster than `min_block_duration` (e.g., 1 s actual, clamped to 2 s):**
`avg_block_duration` is doubled relative to reality. Every block distributes 2× the intended STRK/BTC rewards. Stakers and pool members receive excess yield that the minting curve never authorised, constituting **theft of unclaimed yield** (High) and potential **protocol insolvency** (Critical) if sustained.

**Case B — blocks slower than `max_block_duration` (e.g., 10 s actual, clamped to 5 s):**
`avg_block_duration` is halved relative to reality. Every block distributes only half the yield stakers are entitled to. The shortfall is never recovered in subsequent epochs, constituting **permanent freezing of unclaimed yield** (High).

Both cases map directly to allowed impacts in the bounty scope.

### Likelihood Explanation

Starknet block times are not guaranteed to stay within [2 s, 5 s] across all network conditions. Sequencer upgrades, congestion, or deliberate throughput changes can push the epoch-average outside this band. The default `min=2 s` is already close to current observed block times (~2–3 s), so the lower bound is easily reached. The clamping fires silently every epoch that the average drifts out of range; no special attacker action is required beyond the normal attestation flow that any registered staker triggers.

### Recommendation

Replace the silent clamp with an explicit check and revert (or at minimum emit a warning event and fall back to the previous epoch's value):

```cairo
assert!(
    calculated_block_duration >= block_duration_config.min_block_duration
        && calculated_block_duration <= block_duration_config.max_block_duration,
    "Block duration out of configured bounds"
);
self.avg_block_duration.write(calculated_block_duration);
```

Alternatively, if clamping is intentional for liveness, the bounds should be documented as a known source of reward approximation error and the band should be wide enough to cover all realistic Starknet block-time regimes.

### Proof of Concept

1. Deploy the protocol with default `block_duration_config` (`min=200`, `max=500`).
2. Simulate an epoch where Starknet produces blocks at ~1 s each (e.g., `time_delta=100`, `num_blocks=100` → `calculated_block_duration = 100 * 100 / 100 = 100`, below `min=200`).
3. A staker calls `attest`; the attestation contract calls `update_rewards_from_attestation_contract` on the staking contract, which calls `update_current_epoch_block_rewards` on the reward supplier.
4. `set_avg_block_duration` clamps `100` → `200` and writes `200` to storage.
5. `update_current_epoch_block_rewards` reads `avg_block_duration = 200` and computes `total_rewards = yearly_mint * 200 / (100 * SECONDS_IN_YEAR)` — exactly 2× the correct value of `yearly_mint * 100 / (100 * SECONDS_IN_YEAR)`.
6. The staking contract distributes these inflated rewards to all stakers and pool members for the epoch, with no mechanism to claw them back. [3](#0-2) [4](#0-3)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L40-42)
```text
    pub(crate) const DEFAULT_BLOCK_DURATION_CONFIG: BlockDurationConfig = BlockDurationConfig {
        min_block_duration: 2 * BLOCK_DURATION_SCALE, max_block_duration: 5 * BLOCK_DURATION_SCALE,
    };
```

**File:** src/reward_supplier/reward_supplier.cairo (L166-187)
```text
        fn update_current_epoch_block_rewards(ref self: ContractState) -> (Amount, Amount) {
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
            self.set_avg_block_duration();
            // Calculate block rewards for the current epoch.
            let minting_curve_dispatcher = self.minting_curve_dispatcher.read();
            let yearly_mint = minting_curve_dispatcher.yearly_mint();
            let avg_block_duration = self.avg_block_duration.read();
            let total_rewards = mul_wide_and_div(
                lhs: yearly_mint,
                rhs: avg_block_duration.into(),
                div: BLOCK_DURATION_SCALE.into() * SECONDS_IN_YEAR.into(),
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW);
            let btc_rewards = calculate_btc_rewards(:total_rewards);
            let strk_rewards = total_rewards - btc_rewards;
            (strk_rewards, btc_rewards)
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L369-380)
```text
            let mut calculated_block_duration = mul_wide_and_div(
                lhs: time_delta, rhs: BLOCK_DURATION_SCALE, div: num_blocks,
            )
                .expect_with_err(err: Error::BLOCK_DURATION_OVERFLOW);
            // Adjust calculated_block_duration with min and max block duration.
            let block_duration_config = self.block_duration_config.read();
            calculated_block_duration = calculated_block_duration
                .clamp(
                    block_duration_config.min_block_duration,
                    block_duration_config.max_block_duration,
                );
            self.avg_block_duration.write(calculated_block_duration);
```
