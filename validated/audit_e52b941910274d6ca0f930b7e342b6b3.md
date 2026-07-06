### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Grief Staker Rewards - (File: `src/staking/staking.cairo`)

### Summary
`update_rewards` in the staking contract is intended to be callable only by the Starkware sequencer (per spec), but the implementation enforces **no caller check**. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block without distributing any rewards. This permanently prevents the legitimate sequencer from distributing block rewards for that block, causing stakers and delegators to lose unclaimed yield.

### Finding Description
The `update_rewards` function in `StakingRewardsManagerImpl` uses a single global `last_reward_block` storage variable as a per-block gate: [1](#0-0) 

The check at line 1454–1458 ensures only one call per block is accepted. Once `last_reward_block` is set to the current block, all subsequent calls revert with `REWARDS_ALREADY_UPDATED`.

The function then writes `last_reward_block` **before** checking `disable_rewards`: [2](#0-1) 

If `disable_rewards: true`, the function returns immediately after writing `last_reward_block`, distributing zero rewards. The sequencer's subsequent call with `disable_rewards: false` will revert because `last_reward_block` already equals the current block.

The spec explicitly states access control is "Only starkware sequencer": [3](#0-2) 

But the implementation only calls `general_prerequisites()` (a pause check), with **no caller identity check**. Tests confirm this — `update_rewards` is called in tests without any `cheat_caller_address_once`: [4](#0-3) 

### Impact Explanation
An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in every block causes all stakers and their delegators to receive zero block rewards indefinitely. This constitutes **permanent freezing of unclaimed yield** (High) and effectively **theft of unclaimed yield** (High), since rewards that should have accrued are permanently lost — they are never minted into `unclaimed_rewards_own` or transferred to delegation pools. [5](#0-4) 

### Likelihood Explanation
The attack requires no capital, no privileged role, and no special setup — only a valid active staker address (publicly readable from chain state) and the gas cost of one transaction per block. On Starknet, transaction fees are low. The attacker has no profit motive but causes severe, sustained damage to all stakers and delegators. The attack is trivially repeatable every block.

### Recommendation
Add a caller check at the top of `update_rewards` to enforce that only the authorized sequencer address (or a designated rewards manager role) can invoke it, consistent with the spec's stated access control. For example:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.roles.only_sequencer(); // enforce spec: "Only starkware sequencer"
    self.general_prerequisites();
    ...
}
```

Alternatively, move the `last_reward_block.write` to after the `disable_rewards` branch so that a call with `disable_rewards: true` does not consume the block slot.

### Proof of Concept
1. Staker Alice stakes STRK and becomes active after K epochs.
2. Consensus rewards are active.
3. In every new block, attacker Eve calls:
   ```
   staking.update_rewards(staker_address: alice, disable_rewards: true)
   ```
4. `last_reward_block` is set to the current block; no rewards are distributed.
5. The Starkware sequencer's call to `update_rewards(alice, disable_rewards: false)` reverts with `REWARDS_ALREADY_UPDATED`.
6. Alice and her delegators receive zero block rewards for every block Eve front-runs.
7. Eve repeats this every block at negligible cost, permanently freezing all staker and delegator yield. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1447-1458)
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

**File:** src/staking/staking.cairo (L2349-2363)
```text
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
