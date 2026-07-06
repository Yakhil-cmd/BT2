### Title
Unpermissioned `disable_rewards` Flag in `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield — (`File: src/staking/staking.cairo`)

---

### Summary
The `update_rewards` function in the Staking contract is publicly callable with no restriction on the `disable_rewards` parameter. Because a single global `last_reward_block` gates all reward distribution per block, any unprivileged caller can invoke `update_rewards(any_valid_staker, disable_rewards: true)` at the start of every block, consuming the block's reward slot without distributing rewards. This permanently freezes unclaimed yield for all stakers.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is an externally callable function with no access-control guard beyond the generic `general_prerequisites()` (which only checks pause state and non-zero caller). [1](#0-0) 

The function enforces a single global `last_reward_block` check: [2](#0-1) 

Once the check passes, `last_reward_block` is unconditionally written to the current block number: [3](#0-2) 

Immediately after, if `disable_rewards` is `true`, the function returns early without distributing any rewards: [4](#0-3) 

There is no check that the caller is the staker, the staker's operational address, or any privileged role. Any address can supply `disable_rewards: true` for any valid active staker.

The `last_reward_block` field is a single contract-wide value: [5](#0-4) 

Because it is global, one successful call per block with `disable_rewards: true` prevents every other staker from receiving rewards in that block — any subsequent call in the same block fails with `REWARDS_ALREADY_UPDATED`.

---

### Impact Explanation

In the consensus-rewards epoch (V3, i.e., after `consensus_rewards_first_epoch` is set), `update_rewards` is the sole mechanism for per-block reward distribution to stakers. An attacker who front-runs the first transaction of every block with `update_rewards(any_valid_staker, disable_rewards: true)` permanently prevents all stakers from accumulating unclaimed yield. The rewards for each skipped block are never credited to `unclaimed_rewards_own` and are never requested from the reward supplier, so they are irrecoverably lost.

This matches the allowed impact: **Permanent freezing of unclaimed yield** (High).

---

### Likelihood Explanation

- The attacker needs only a valid, active staker address with non-zero balance — trivially obtained from on-chain events.
- The attacker needs to be first in each block. On Starknet, transaction ordering within a block is sequencer-controlled, but an attacker can submit a low-fee transaction at the start of every block with high reliability.
- No privileged access, leaked key, or external dependency is required.
- The attack is cheap: one transaction per block, no stake required.

---

### Recommendation

Restrict the `disable_rewards` path to a privileged caller (e.g., the staker's own address, the operational address, or a dedicated protocol role), or remove the `disable_rewards` parameter from the public interface entirely and handle the "no-reward" case through a separate privileged function. At minimum, add a caller check analogous to the one used in `update_rewards_from_attestation_contract`: [6](#0-5) 

---

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and the current epoch has passed it).
2. A valid staker `S` exists with non-zero STRK balance.
3. Attacker `A` (any EOA) submits at the start of block `N`:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The call passes all checks: contract is unpaused, `block_N > last_reward_block`, staker `S` is active with non-zero balance.
5. `last_reward_block` is written to `block_N`; the function returns early — no rewards distributed.
6. Any legitimate call to `update_rewards` for any staker in block `N` now reverts with `REWARDS_ALREADY_UPDATED`.
7. Attacker repeats step 3 every block. All stakers permanently receive zero yield. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1449-1507)
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

            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

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
        }
```
