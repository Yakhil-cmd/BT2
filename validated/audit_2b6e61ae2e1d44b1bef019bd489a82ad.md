### Title
Wrong Aggregate Variable Used in Consensus Reward Calculation — (`File: src/staking/staking.cairo`)

### Summary

`update_rewards` (the consensus-based per-block reward path) passes the **individual staker's own balance** as the `strk_total_stake` / `btc_total_stake` denominator to `_update_rewards`, whereas the attestation-based path (`update_rewards_from_attestation_contract`) correctly passes the **global total staking power**. This is a direct accounting analog to the external report's `totalSupply` not being maintained: the wrong aggregate variable is used in the reward-share calculation.

### Finding Description

`_update_rewards` is called from two sites with the same parameter names but different values:

**Attestation path (correct):** [1](#0-0) 

```cairo
let (strk_epoch_rewards, btc_epoch_rewards) = reward_supplier_dispatcher
    .calculate_current_epoch_rewards();
let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power(); // ← global
self._update_rewards(
    ...
    strk_total_rewards: strk_epoch_rewards,
    :strk_total_stake,   // global total
    :btc_total_stake,    // global total
    ...
);
```

**Consensus path (buggy):** [2](#0-1) 

```cairo
let (staker_total_strk_balance, staker_total_btc_balance) = self
    .get_staker_total_strk_btc_balance_at_epoch(
        :staker_address, :staker_pool_info, epoch_id: curr_epoch,
    );
...
let (strk_block_rewards, btc_block_rewards) = self
    .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
self._update_rewards(
    ...
    strk_total_rewards: strk_block_rewards,
    strk_total_stake: staker_total_strk_balance,  // ← staker's own balance, NOT global
    btc_total_stake:  staker_total_btc_balance,   // ← staker's own balance, NOT global
    ...
);
```

`_update_rewards` uses `strk_total_stake` as the denominator for proportional reward share (the same role it plays in `get_staker_staking_power_at_epoch`): [3](#0-2) 

When the denominator equals the numerator (staker's own balance / staker's own balance = 1), the staker receives **100% of the total block rewards** instead of their proportional share.

The block rewards value (`strk_block_rewards`) is the **total** epoch block reward for all stakers, cached in `self.block_rewards` and shared across all callers: [4](#0-3) 

### Impact Explanation

`update_rewards` is a public function callable by any address: [5](#0-4) 

The `last_reward_block` guard allows exactly one successful call per block. The first caller each block passes their staker's balance as the denominator, causing `_update_rewards` to credit that staker with the **entire** block reward pool. All other stakers receive zero rewards for that block. Repeated over many blocks, this constitutes **theft of unclaimed yield** from all other stakers and drains the reward supplier, leading to **protocol insolvency**.

**Impact: Critical — Protocol insolvency / Direct theft of yield at scale.**

### Likelihood Explanation

`update_rewards` is permissionless and callable by any address with any `staker_address`. A rational attacker simply calls it first in every block. No privileged access, no leaked keys, no external dependencies are required. The only prerequisite is being a registered staker (minimum stake).

### Recommendation

Replace the staker-local balance with the global total staking power in `update_rewards`, mirroring the attestation path:

```cairo
// Replace:
strk_total_stake: staker_total_strk_balance,
btc_total_stake:  staker_total_btc_balance,

// With:
let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
strk_total_stake: strk_total_stake,
btc_total_stake:  btc_total_stake,
```

### Proof of Concept

1. Alice stakes the minimum amount and becomes a registered staker.
2. Each block, Alice calls `update_rewards(staker_address: alice)` before any other staker.
3. `_update_rewards` receives `strk_total_stake = alice_balance` and `strk_total_rewards = total_block_rewards`.
4. Alice's reward share = `total_block_rewards * alice_balance / alice_balance` = `total_block_rewards` (100%).
5. All other stakers receive 0 rewards for that block.
6. Over an epoch, Alice drains the reward supplier of all consensus-based block rewards, starving every other staker and causing protocol insolvency.

### Citations

**File:** src/staking/staking.cairo (L1406-1422)
```text
            let (strk_epoch_rewards, btc_epoch_rewards) = reward_supplier_dispatcher
                .calculate_current_epoch_rewards();
            let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let curr_epoch = self.get_current_epoch();
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_epoch_rewards,
                    btc_total_rewards: btc_epoch_rewards,
                    :strk_total_stake,
                    :btc_total_stake,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
```

**File:** src/staking/staking.cairo (L1449-1458)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1474-1506)
```text
            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
```

**File:** src/staking/staking.cairo (L1558-1571)
```text
        fn calculate_block_rewards(
            ref self: ContractState,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) -> (Amount, Amount) {
            if curr_epoch > self.last_calculated_epoch.read() {
                self.last_calculated_epoch.write(curr_epoch);
                let block_rewards = reward_supplier_dispatcher.update_current_epoch_block_rewards();
                self.block_rewards.write(block_rewards);
                block_rewards
            } else {
                self.block_rewards.read()
            }
        }
```

**File:** src/staking/staking.cairo (L2388-2410)
```text
        fn get_staker_staking_power_at_epoch(
            self: @ContractState,
            staker_address: ContractAddress,
            epoch_id: Epoch,
            strk_total_stake: NormalizedAmount,
            btc_total_stake: NormalizedAmount,
        ) -> StakingPower {
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            let (staker_strk_total_amount, staker_btc_total_amount) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, :epoch_id,
                );
            if staker_strk_total_amount.is_zero() {
                return Zero::zero();
            }

            calculate_staker_total_staking_power(
                :staker_strk_total_amount,
                :staker_btc_total_amount,
                :strk_total_stake,
                :btc_total_stake,
            )
        }
```
