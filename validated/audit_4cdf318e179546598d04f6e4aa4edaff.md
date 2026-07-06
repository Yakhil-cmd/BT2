### Title
Inconsistent `strk_total_stake` Argument in `_update_rewards` Between Consensus and Pre-Consensus Reward Paths — (File: `src/staking/staking.cairo`)

### Summary

The `update_rewards` function (consensus mode) passes the **staker's own balance** as the `strk_total_stake` argument to `_update_rewards`, while `update_rewards_from_attestation_contract` (pre-consensus mode) correctly passes the **total protocol staking power**. This mirrors the SapienVault pattern exactly: two operations that invoke the same internal calculation function use fundamentally different values for the same denominator parameter, allowing a staker to game the reward distribution.

### Finding Description

In `update_rewards_from_attestation_contract` (pre-consensus path):

```cairo
let (strk_epoch_rewards, btc_epoch_rewards) = reward_supplier_dispatcher
    .calculate_current_epoch_rewards();
let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
// ...
self._update_rewards(
    :staker_address,
    strk_total_rewards: strk_epoch_rewards,
    btc_total_rewards: btc_epoch_rewards,
    :strk_total_stake,          // ← total protocol stake (correct)
    :btc_total_stake,
    ...
);
``` [1](#0-0) 

In `update_rewards` (consensus path):

```cairo
let (staker_total_strk_balance, staker_total_btc_balance) = self
    .get_staker_total_strk_btc_balance_at_epoch(
        :staker_address, :staker_pool_info, epoch_id: curr_epoch,
    );
// ...
self._update_rewards(
    :staker_address,
    strk_total_rewards: strk_block_rewards,
    btc_total_rewards: btc_block_rewards,
    strk_total_stake: staker_total_strk_balance,   // ← staker's own balance (wrong)
    btc_total_stake: staker_total_btc_balance,
    ...
);
``` [2](#0-1) 

The standard reward share formula inside `_update_rewards` is:

```
staker_rewards = total_rewards × staker_balance / strk_total_stake
```

When `strk_total_stake = staker_balance`, the division cancels and the staker receives **all** block rewards (`strk_block_rewards`) regardless of their actual share of the protocol.

The entry point is fully public — `general_prerequisites()` only checks the contract is unpaused and the caller is non-zero: [3](#0-2) 

The only per-block rate-limit is `current_block_number > self.last_reward_block`, which a staker can satisfy by calling once per block: [4](#0-3) 

### Impact Explanation

A staker in consensus mode calls `update_rewards(staker_address: self, disable_rewards: false)` once per block. Because `strk_total_stake` equals their own balance, `_update_rewards` attributes 100 % of `strk_block_rewards` to them. All other stakers receive zero rewards for every block the attacker front-runs. This constitutes **theft of unclaimed yield** from all other protocol participants and, at scale, **protocol insolvency** as the reward supplier is drained at the full block-reward rate by a single actor.

### Likelihood Explanation

The function is callable by any non-zero address with no role check. Consensus rewards are active once `consensus_rewards_first_epoch` is set. Any staker who discovers the inconsistency can exploit it every block with a simple script. Likelihood is **high** once the consensus reward regime is live.

### Recommendation

Replace the staker's own balance with the total protocol staking power in the `update_rewards` consensus path, matching the attestation path:

```cairo
// Replace:
strk_total_stake: staker_total_strk_balance,
btc_total_stake:  staker_total_btc_balance,

// With:
let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
// pass strk_total_stake, btc_total_stake to _update_rewards
```

### Proof of Concept

1. Protocol enters consensus reward mode (`consensus_rewards_first_epoch` is set and reached).
2. Attacker (any registered staker) calls `update_rewards(attacker_address, false)` at the first transaction of every block.
3. Inside `_update_rewards`, `strk_total_stake = attacker_balance`. The formula `strk_block_rewards × attacker_balance / attacker_balance` yields `strk_block_rewards` — the full block reward.
4. Attacker's `unclaimed_rewards_own` accumulates the entire protocol block reward each block.
5. All other stakers' `_update_rewards` calls (if any) receive zero because `last_reward_block` is already updated, triggering `REWARDS_ALREADY_UPDATED`.
6. Attacker calls `claim_rewards` to extract the accumulated yield.

### Citations

**File:** src/staking/staking.cairo (L1404-1423)
```text
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            // Get current epoch data.
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
        }
```

**File:** src/staking/staking.cairo (L1453-1458)
```text
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
