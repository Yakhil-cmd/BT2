### Title
Pre-Consensus Epoch Reward Over-Minting Due to Block-Number-Based Epoch Boundaries with Fixed `epoch_duration` Assumption — (File: `src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The `calculate_current_epoch_rewards` function distributes per-epoch rewards by dividing `yearly_mint` by `epochs_in_year`, where `epochs_in_year = SECONDS_IN_YEAR / epoch_duration`. However, epoch boundaries are determined entirely by block numbers via `EpochInfo.current_epoch()`. Since Starknet's block time is not constant, the actual number of epochs that occur per year can diverge from the assumed `epochs_in_year`, causing cumulative over- or under-minting during the pre-consensus rewards phase.

---

### Finding Description

`EpochInfo` stores two independent parameters: `epoch_duration` (seconds, used for reward math) and `length` (blocks, used for epoch boundary detection). [1](#0-0) 

Epoch boundaries are resolved purely from block numbers: [2](#0-1) 

`epochs_in_year` is derived from the admin-configured `epoch_duration` in seconds, not from observed block time: [3](#0-2) 

`calculate_current_epoch_rewards` (used before consensus rewards are activated, per the spec) distributes `yearly_mint / epochs_in_year` per epoch: [4](#0-3) 

The admin sets `epoch_duration` and `epoch_length` at deployment time based on the current average block time. If Starknet's block production rate changes after deployment (which it does — Starknet block time is not constant), the two parameters diverge:

- `epoch_duration` stays fixed at the admin-configured value.
- Actual epoch wall-clock duration = `length × actual_block_time`, which changes with network conditions.

**Concrete example:** Admin sets `epoch_duration = 3000 s` and `length = 1000 blocks` (assuming 3 s/block). If Starknet later produces blocks at 2 s/block:
- Actual epochs per year = 31,536,000 / 2000 = **15,768**
- Assumed `epochs_in_year` = 31,536,000 / 3000 = **10,512**
- Rewards per epoch = `yearly_mint / 10,512`
- Total annual payout = 15,768 × (`yearly_mint / 10,512`) = **1.5 × yearly_mint**

This is 50% over-minting relative to the intended inflation rate.

The post-consensus reward function `update_current_epoch_block_rewards` correctly uses actual timestamps via `avg_block_duration` and is not affected: [5](#0-4) 

The vulnerability is therefore scoped to the pre-consensus rewards phase, which is the active mode until `consensus_rewards_first_epoch` is reached. [6](#0-5) 

---

### Impact Explanation

During the pre-consensus rewards phase, every epoch that completes faster than `epoch_duration` seconds causes the reward supplier to pay out `yearly_mint / epochs_in_year` in excess of the intended annual budget. Over a sustained period of faster block production, cumulative over-minting depletes the reward supplier's STRK balance ahead of schedule, leading to:

- **Theft of unclaimed yield** — stakers and delegators collectively receive more STRK than the protocol's inflation model authorises.
- **Protocol insolvency** — the reward supplier exhausts its L1-bridged STRK balance before the end of the intended distribution period, causing `claim_rewards` calls to fail for later claimants.

Both map to allowed impacts (High / Critical).

---

### Likelihood Explanation

Starknet's block time is empirically non-constant and has varied historically. The admin-set `epoch_duration` is a static parameter that is only updated via a privileged `set_epoch_info` call. Any sustained deviation in block time between admin updates directly translates to proportional reward inaccuracy. No attacker action is required; the divergence occurs passively as network conditions change.

---

### Recommendation

For the pre-consensus rewards path, derive `epochs_in_year` from observed block timestamps rather than the static `epoch_duration` parameter, mirroring the approach already used in `update_current_epoch_block_rewards` via `avg_block_duration`. Alternatively, gate `calculate_current_epoch_rewards` so it is only callable when `avg_block_duration` has been initialised, and use it in the reward formula:

```
epochs_in_year ≈ (SECONDS_IN_YEAR * BLOCK_DURATION_SCALE) / (avg_block_duration * epoch_len_in_blocks)
```

This ensures the per-epoch reward automatically tracks actual network throughput, consistent with the fix applied in the referenced Berachain report.

---

### Proof of Concept

1. Protocol is deployed with `epoch_duration = 3000` s, `epoch_length = 1000` blocks, `yearly_mint = 1,000,000 STRK`. Consensus rewards are not yet activated.
2. Starknet block time drops from 3 s to 2 s (a realistic scenario given variable block production).
3. Each 1000-block epoch now completes in ~2000 s instead of 3000 s.
4. `epochs_in_year = 31,536,000 / 3000 = 10,512` (unchanged).
5. Actual epochs per year = 31,536,000 / 2000 = 15,768.
6. Each epoch pays `1,000,000 / 10,512 ≈ 95.1 STRK`.
7. Annual payout = 15,768 × 95.1 ≈ **1,499,573 STRK** instead of 1,000,000 STRK.
8. The reward supplier's L1-bridged balance is exhausted ~50% earlier than planned, causing `claim_rewards` to revert for stakers who have not yet claimed, permanently freezing their unclaimed yield. [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/objects.cairo (L151-164)
```text
pub(crate) struct EpochInfo {
    /// The duration of the epoch in seconds.
    epoch_duration: u32,
    /// The length of the epoch in blocks.
    length: u32,
    /// The first block of the first epoch with this length.
    starting_block: BlockNumber,
    /// The first epoch id with this length, changes by a call to update.
    starting_epoch: Epoch,
    /// The length of the epoch prior to the update.
    previous_length: u32,
    /// The duration of the epoch prior to the update.
    previous_epoch_duration: u32,
}
```

**File:** src/staking/objects.cairo (L186-192)
```text
    fn current_epoch(self: @EpochInfo) -> Epoch {
        if self.update_done_in_this_epoch() {
            return *self.starting_epoch - 1;
        }
        ((get_block_number() - *self.starting_block) / self.epoch_len_in_blocks().into())
            + *self.starting_epoch
    }
```

**File:** src/staking/objects.cairo (L213-221)
```text
    /// Get the number of expected epochs in a year base on the current epoch duration.
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

**File:** src/staking/staking.cairo (L187-199)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
        consensus_rewards_first_epoch: Epoch,
        /// The class hash of the pool EIC contract.
        /// The EIC contract is used while upgrading pool contracts from V1 / V2 (BTC) to V3.
        /// Only used in `staker_migration`.
        pool_eic_class_hash: ClassHash,
        /// Map staker address to its version.
        staker_version: Map<ContractAddress, StakerVersion>,
        /// Last epoch for which block rewards were calculated.
        last_calculated_epoch: Epoch,
        /// Block rewards (STRK, BTC) for the current epoch.
        block_rewards: (Amount, Amount),
```
