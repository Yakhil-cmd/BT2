### Title
Missing Admin Setter for `avg_block_duration` Acknowledged by `TODO` Comment Causes Incorrect Consensus Reward Calculations - (`src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The `RewardSupplier` contract stores `avg_block_duration` as a critical parameter used to compute per-block consensus rewards. The developers explicitly marked it with `// TODO: Setter.` but never implemented one. Without an admin setter, the value is stuck at `DEFAULT_AVG_BLOCK_DURATION` for the entire first epoch of consensus rewards, and there is no privileged path to correct it if the auto-calculated value diverges from reality.

---

### Finding Description

In `src/reward_supplier/reward_supplier.cairo`, the storage field `avg_block_duration` is declared with an explicit developer acknowledgment that a setter is missing:

```cairo
/// Average block duration in units of 1 / BLOCK_DURATION_SCALE seconds.
// TODO: Setter.
// TODO: View?
avg_block_duration: u64,
``` [1](#0-0) 

The constructor initializes it to `DEFAULT_AVG_BLOCK_DURATION = 3 * BLOCK_DURATION_SCALE = 300` (representing 3 seconds per block):

```cairo
self.avg_block_duration.write(DEFAULT_AVG_BLOCK_DURATION);
``` [2](#0-1) 

This value is used directly in `update_current_epoch_block_rewards` to compute per-block rewards:

```cairo
let total_rewards = mul_wide_and_div(
    lhs: yearly_mint,
    rhs: avg_block_duration.into(),
    div: BLOCK_DURATION_SCALE.into() * SECONDS_IN_YEAR.into(),
)
``` [3](#0-2) 

The internal `set_avg_block_duration` function does auto-update `avg_block_duration` each epoch, but it relies on `block_snapshot`, which is **never initialized in the constructor** (defaults to `(0, 0)`). On the very first call, `set_avg_block_duration` detects a zero snapshot, writes the current block data, and **returns early without updating `avg_block_duration`**:

```cairo
if snapshot_block_number.is_zero() || snapshot_timestamp.is_zero() {
    return;
}
``` [4](#0-3) 

This means for the entire first epoch of consensus rewards, `avg_block_duration` remains at the hardcoded default of 3 seconds. There is no admin function in `IRewardSupplierConfig` to override it:

```cairo
pub trait IRewardSupplierConfig<TContractState> {
    fn set_block_duration_config(
        ref self: ContractState, block_duration_config: BlockDurationConfig,
    );
}
``` [5](#0-4) 

Only `set_block_duration_config` exists, which adjusts the min/max clamp bounds — it does not directly set `avg_block_duration`. If the actual Starknet block time differs from 3 seconds (e.g., 6 seconds), rewards for the first consensus epoch are miscalculated by a proportional factor, with no admin recourse.

---

### Impact Explanation

`avg_block_duration` directly scales the per-block reward amount. If actual block time is 6 seconds but the default is 3 seconds, stakers receive **half** the expected rewards for the first consensus epoch. These rewards are permanently lost — they are never re-distributed. This constitutes permanent freezing of unclaimed yield for all stakers and pool members during the first consensus epoch.

**Allowed impact matched:** High — Permanent freezing of unclaimed yield.

---

### Likelihood Explanation

This condition is triggered exactly once per deployment: during the first epoch of consensus rewards. Every deployment of the `RewardSupplier` contract is affected. The Starknet network's actual block production rate may differ from the hardcoded 3-second default, making this a realistic scenario rather than a theoretical one.

---

### Recommendation

Implement the missing admin setter for `avg_block_duration`, as the `TODO: Setter.` comment already acknowledges:

```cairo
fn set_avg_block_duration_override(ref self: ContractState, avg_block_duration: u64) {
    self.roles.only_app_governor();
    let block_duration_config = self.block_duration_config.read();
    assert!(
        avg_block_duration >= block_duration_config.min_block_duration
            && avg_block_duration <= block_duration_config.max_block_duration,
        "{}",
        Error::INVALID_MIN_MAX_BLOCK_DURATION,
    );
    self.avg_block_duration.write(avg_block_duration);
}
```

This allows the `app_governor` to correct the value before or during the first consensus epoch, consistent with the existing `set_block_duration_config` access pattern.

---

### Proof of Concept

1. The `RewardSupplier` is deployed. `avg_block_duration = 300` (3 seconds). `block_snapshot = (0, 0)`.
2. The `app_governor` calls `set_consensus_rewards_first_epoch(epoch_id)` on the Staking contract.
3. This triggers `calculate_block_rewards` → `update_current_epoch_block_rewards` → `set_avg_block_duration`.
4. Inside `set_avg_block_duration`, `snapshot_block_number == 0`, so the function writes the current snapshot and **returns early**. `avg_block_duration` remains `300`.
5. For the entire first consensus epoch, every call to `update_rewards` computes block rewards using `avg_block_duration = 300`.
6. If actual Starknet block time is 6 seconds (`600` in scaled units), all stakers receive 50% of their correct rewards for this epoch.
7. There is no function in `IRewardSupplierConfig` to correct `avg_block_duration`. The only recourse is a full contract upgrade. [6](#0-5) [7](#0-6)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L86-90)
```text
        /// Average block duration in units of 1 / BLOCK_DURATION_SCALE seconds.
        // TODO: Setter.
        // TODO: View?
        avg_block_duration: u64,
        /// The latest block data used for average block duration calculation.
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

**File:** src/reward_supplier/reward_supplier.cairo (L273-296)
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
