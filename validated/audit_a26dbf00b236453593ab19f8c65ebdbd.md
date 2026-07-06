### Title
Unprivileged Caller Can Permanently Freeze All Staker Consensus Rewards via Unguarded `disable_rewards` Flag in `update_rewards` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards: bool` parameter with no authorization check. Because the global `last_reward_block` is written unconditionally before the `disable_rewards` branch, any unprivileged address can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block to consume the single allowed reward-update slot for that block without distributing any rewards. Sustained across every block, this permanently freezes all stakers' consensus-era unclaimed yield.

---

### Finding Description

`update_rewards` is exposed as a public entry point under `IStakingRewardsManager`. Its only gate is `general_prerequisites()`, which checks the pause flag and that the caller is non-zero — no role or identity check is performed. [1](#0-0) 

The function immediately writes the current block number to the **global** `last_reward_block` storage slot: [2](#0-1) 

Only *after* that write does it branch on `disable_rewards`: [3](#0-2) 

Because `last_reward_block` is a single contract-wide field (not per-staker), the guard at the top of the function: [4](#0-3) 

…means exactly **one** call is permitted per block for the entire protocol. An attacker who wins that slot with `disable_rewards: true` silently discards the block's rewards for every staker, and no legitimate caller can reclaim the slot until the next block.

The `last_reward_block` storage declaration confirms it is a single scalar, not a map: [5](#0-4) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

By calling `update_rewards(any_active_staker, disable_rewards: true)` in every block, an attacker prevents the `_update_rewards` path from ever executing: [6](#0-5) 

Stakers' `unclaimed_rewards_own` fields are never incremented, pool reward traces are never updated, and the `RewardSupplier` is never notified. The yield that should have accrued is permanently lost — it is never minted or credited anywhere.

---

### Likelihood Explanation

The attack requires one cheap transaction per block. The attacker needs no stake, no role, and no special access — only a funded address. The `staker_address` argument can be any currently active staker (trivially discoverable from on-chain events). There is no economic barrier and no protocol mechanism to detect or prevent the pattern. The attack is fully permissionless and can be automated.

---

### Recommendation

Restrict `update_rewards` to a trusted caller (e.g., the sequencer/block-proposer address, or a dedicated role), or remove the `disable_rewards` parameter and handle the pre-consensus short-circuit internally based on `is_pre_consensus()` alone, so that no external caller can suppress reward distribution.

---

### Proof of Concept

```
Block N:
  Attacker → staking.update_rewards(active_staker, disable_rewards=true)
    → last_reward_block := N          // slot consumed
    → disable_rewards == true → return // no rewards distributed

  Legitimate caller → staking.update_rewards(active_staker, disable_rewards=false)
    → assert(N > N) FAILS → REWARDS_ALREADY_UPDATED

Block N+1: attacker repeats.
...
All stakers: unclaimed_rewards_own never increases. Yield permanently frozen.
```

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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

**File:** src/staking/staking.cairo (L1484-1507)
```text
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
