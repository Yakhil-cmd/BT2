### Title
Unrestricted `update_rewards` with Caller-Controlled `disable_rewards` Permanently Freezes Consensus Block Rewards - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract has no access control and accepts a fully caller-controlled `disable_rewards` boolean. Any unprivileged address can call `update_rewards(any_active_staker, disable_rewards: true)` to consume the global `last_reward_block` slot for the current block without distributing any rewards. This permanently prevents the legitimate block proposer from claiming consensus rewards for that block. The attack can be repeated every block, permanently freezing all consensus-regime yield.

---

### Finding Description

`update_rewards` is exposed as a public ABI function with no caller restriction: [1](#0-0) 

The function accepts two attacker-controlled inputs: `staker_address` (any active staker) and `disable_rewards` (any boolean). Critically, the global `last_reward_block` is written **before** the `disable_rewards` branch is evaluated: [2](#0-1) 

After writing `last_reward_block`, the function returns immediately if `disable_rewards` is `true`, distributing nothing: [3](#0-2) 

The guard that prevents double-rewarding per block checks this same global variable: [4](#0-3) 

Because `last_reward_block` is a single global field (not per-staker), once any caller consumes it for block N, no other call can succeed in block N: [5](#0-4) 

The attack path:

1. Attacker calls `update_rewards(any_active_staker, disable_rewards: true)` in block N.
2. `last_reward_block` is set to N; no rewards are minted or distributed.
3. The legitimate block proposer calls `update_rewards(proposer, disable_rewards: false)` in block N.
4. The call reverts with `REWARDS_ALREADY_UPDATED` because `current_block_number == last_reward_block`.
5. The proposer's yield for block N is permanently lost.

The attacker only needs to supply a valid, active staker address with non-zero balance — all of which are public on-chain via the `stakers` vector and `staker_info` map: [6](#0-5) 

This attack is only relevant in the consensus-rewards regime (`is_pre_consensus() == false`), which is the live production path once `consensus_rewards_first_epoch` is reached.

---

### Impact Explanation

Each block's consensus reward is permanently lost when the slot is consumed with `disable_rewards: true`. The `last_reward_block` value cannot be rolled back; there is no recovery path. An attacker who submits this call in every block permanently freezes all consensus-regime yield for every staker. This matches:

**High: Permanent freezing of unclaimed yield or unclaimed royalties.**

---

### Likelihood Explanation

- No privileged role, leaked key, or special knowledge is required.
- The attacker only needs any active staker address (publicly enumerable).
- The cost is one transaction per block.
- On Starknet, where the sequencer orders transactions, an attacker can reliably submit this call before the legitimate proposer's `update_rewards` call in each block.
- The attack is fully permissionless and repeatable indefinitely.

Likelihood: **High**.

---

### Recommendation

Restrict `update_rewards` so that only the staker themselves, their registered operational address, or a designated on-chain rewards manager may call it. At minimum, the `disable_rewards: true` path should require the caller to be the staker or their operational address, preventing an unprivileged third party from consuming the block's reward slot without distributing rewards.

---

### Proof of Concept

```
// Setup: staker_A is an active staker with non-zero balance (epoch >= K after stake).
// Block N is the current block.

// Step 1 — Attacker (any address) front-runs the block proposer:
staking.update_rewards(staker_address: staker_A, disable_rewards: true);
// Result: last_reward_block = N, no rewards distributed.

// Step 2 — Legitimate block proposer attempts to claim rewards:
staking.update_rewards(staker_address: proposer, disable_rewards: false);
// Result: PANICS with "Rewards already updated for this block"
//         because current_block_number (N) == last_reward_block (N).

// Step 3 — Proposer's yield for block N is permanently lost.
// Attacker repeats Step 1 in every subsequent block to freeze all consensus rewards.
``` [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1447-1507)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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
