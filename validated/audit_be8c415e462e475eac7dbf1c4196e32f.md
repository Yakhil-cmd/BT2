### Title
Missing Admin Setter for `avg_block_duration` Leaves Consensus Block Rewards Uncorrectable - (File: `src/reward_supplier/reward_supplier.cairo`)

### Summary
The `RewardSupplier` contract stores `avg_block_duration` — the average block duration used to compute per-block consensus rewards — but provides no external setter for it. The developers explicitly acknowledged this gap with a `// TODO: Setter.` comment. The value is initialized to a hardcoded default and can only be updated by an internal automatic mechanism. If that mechanism produces an incorrect value, the admin has no way to correct it without a full contract upgrade, causing reward miscalculation.

### Finding Description
In `src/reward_supplier/reward_supplier.cairo`, `avg_block_duration` is declared in storage with an explicit developer note:

```cairo
/// Average block duration in units of 1 / BLOCK_DURATION_SCALE seconds.
// TODO: Setter.
// TODO: View?
avg_block_duration: u64,
``` [1](#0-0) 

It is initialized to `DEFAULT_AVG_BLOCK_DURATION` (= `3 * BLOCK_DURATION_SCALE` = 300, representing 3 seconds) in the constructor:

```cairo
self.avg_block_duration.write(DEFAULT_AVG_BLOCK_DURATION);
``` [2](#0-1) 

The only update path is the internal `set_avg_block_duration()` function, called exclusively from `update_current_epoch_block_rewards()`, which is itself restricted to the staking contract: [3](#0-2) 

Critically, the first call to `set_avg_block_duration()` always returns early without updating `avg_block_duration`, because `block_snapshot` is initialized to `(0, 0)`:

```cairo
if snapshot_block_number.is_zero() || snapshot_timestamp.is_zero() {
    return;
}
``` [4](#0-3) 

This means for at least the first consensus epoch, `avg_block_duration` is always the hardcoded default. The `IRewardSupplierConfig` interface exposes only `set_block_duration_config` (for min/max bounds), with no setter for `avg_block_duration` itself: [5](#0-4) 

`avg_block_duration` is used directly in the reward formula:

```cairo
let total_rewards = mul_wide_and_div(
    lhs: yearly_mint,
    rhs: avg_block_duration.into(),
    div: BLOCK_DURATION_SCALE.into() * SECONDS_IN_YEAR.into(),
)
``` [6](#0-5) 

### Impact Explanation
`avg_block_duration` is the sole multiplier controlling how much of the yearly mint is distributed per block. If the actual Starknet block time diverges from the 3-second default (e.g., due to a network upgrade or congestion), rewards are proportionally miscalculated:

- **Too high** (actual blocks faster than default): more rewards distributed per block than intended → theft of unclaimed yield (High).
- **Too low** (actual blocks slower than default): fewer rewards distributed per block than intended → permanent under-distribution / freezing of unclaimed yield (High).

Because there is no setter, the admin cannot correct the value without a full contract upgrade, making any miscalculation persistent across all subsequent epochs until an upgrade is deployed.

### Likelihood Explanation
Starknet block times are not guaranteed to remain at 3 seconds. Protocol upgrades or sequencer changes can shift average block duration. The first consensus epoch is always affected (stuck at default). The `// TODO: Setter.` comment confirms the developers themselves identified this as an unresolved gap. Likelihood is **Medium**: the default is reasonable today, but the missing setter creates a permanent governance blind spot.

### Recommendation
Add a permissioned setter to `IRewardSupplierConfig` and implement it in `RewardSupplierConfigImpl`:

```cairo
fn set_avg_block_duration(ref self: ContractState, avg_block_duration: u64) {
    self.roles.only_app_governor();
    let config = self.block_duration_config.read();
    assert!(
        avg_block_duration >= config.min_block_duration
            && avg_block_duration <= config.max_block_duration,
        "{}",
        Error::INVALID_AVG_BLOCK_DURATION,
    );
    self.avg_block_duration.write(avg_block_duration);
    // emit event
}
```

The new duration must be validated against the existing `block_duration_config` bounds (analogous to the `MAX_COOLDOWN_DURATION` check added in the referenced Level Money fix).

### Proof of Concept

1. `RewardSupplier` is deployed; `avg_block_duration` = 300 (3 s).
2. Starknet undergoes a sequencer upgrade; average block time becomes 6 s.
3. Staking contract calls `update_current_epoch_block_rewards()` each epoch.
4. `set_avg_block_duration()` calculates the real average and clamps it to `[min=200, max=500]` → writes 500 (5 s, the max), not 600 (6 s actual).
5. Even at the clamped max, rewards are computed as if blocks are 5 s, not 6 s — a ~17% under-distribution per epoch.
6. The app governor updates `block_duration_config` to `{min: 200, max: 700}` to allow the correct value, but `avg_block_duration` itself remains at 500 until the next epoch's automatic recalculation.
7. There is no call the admin can make to immediately correct `avg_block_duration` to the accurate value — the missing setter means the protocol must wait a full epoch for the automatic mechanism to self-correct, and any epoch already processed with the wrong value cannot be retroactively fixed. [7](#0-6) [8](#0-7)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L86-89)
```text
        /// Average block duration in units of 1 / BLOCK_DURATION_SCALE seconds.
        // TODO: Setter.
        // TODO: View?
        avg_block_duration: u64,
```

**File:** src/reward_supplier/reward_supplier.cairo (L133-134)
```text
        self.avg_block_duration.write(DEFAULT_AVG_BLOCK_DURATION);
        self.block_duration_config.write(DEFAULT_BLOCK_DURATION_CONFIG);
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

**File:** src/reward_supplier/reward_supplier.cairo (L273-295)
```text
    #[abi(embed_v0)]
    impl RewardSupplierConfigImpl of IRewardSupplierConfig<ContractState> {
        fn set_block_duration_config(
            ref self: ContractState, block_duration_config: BlockDurationConfig,
        ) {
            self.roles.only_app_governor();
            // TODO: Emit event?
            // Assert that block_time_config is valid.
            // TODO: More validations?
            assert!(
                block_duration_config.min_block_duration > 0,
                "{}",
                Error::INVALID_MIN_MAX_BLOCK_DURATION,
            );
            assert!(
                block_duration_config
                    .min_block_duration <= block_duration_config
                    .max_block_duration,
                "{}",
                Error::INVALID_MIN_MAX_BLOCK_DURATION,
            );
            self.block_duration_config.write(block_duration_config);
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L339-381)
```text
        fn set_avg_block_duration(ref self: ContractState) {
            let current_block_number = starknet::get_block_number();
            let current_timestamp = starknet::get_block_timestamp();
            let (snapshot_block_number, snapshot_timestamp) = self.block_snapshot.read();
            // Sanity asserts.
            assert!(
                current_block_number > snapshot_block_number,
                "{}",
                InternalError::INVALID_BLOCK_NUMBER,
            );
            assert!(
                current_timestamp > snapshot_timestamp.into(),
                "{}",
                InternalError::INVALID_BLOCK_TIMESTAMP,
            );
            self
                .block_snapshot
                .write((current_block_number, Timestamp { seconds: current_timestamp }));
            // If this is the first time we're setting the block snapshot, can't calculate avg block
            // time yet.
            if snapshot_block_number.is_zero() || snapshot_timestamp.is_zero() {
                return;
            }
            let time_delta = current_timestamp - snapshot_timestamp.into();
            // *Note*: `num_blocks` should match the epoch length in blocks. This calculation is
            // expected to run on the first block of each epoch, assuming `update_rewards` is called
            // every block.
            // We calculate `num_blocks` instead of using the configured value to keep the average
            // accurate even if some calls are missed.
            let num_blocks = current_block_number - snapshot_block_number;
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
        }
```

**File:** src/reward_supplier/interface.cairo (L85-103)
```text
#[starknet::interface]
pub trait IRewardSupplierConfig<TContractState> {
    /// Sets the block duration configuration.
    ///
    /// #### Preconditions:
    /// - `block_duration_config.min_block_duration > 0`
    /// - `block_duration_config.min_block_duration <= block_duration_config.max_block_duration`
    ///
    /// #### Errors:
    /// - [`ONLY_APP_GOVERNOR`](AccessErrors::ONLY_APP_GOVERNOR)
    /// -
    /// [`INVALID_MIN_MAX_BLOCK_DURATION`](staking::reward_supplier::errors::Error::INVALID_MIN_MAX_BLOCK_DURATION)
    ///
    /// #### Access control:
    /// Only app governor.
    fn set_block_duration_config(
        ref self: TContractState, block_duration_config: BlockDurationConfig,
    );
}
```
