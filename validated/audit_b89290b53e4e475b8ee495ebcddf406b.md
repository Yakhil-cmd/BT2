### Title
Unprivileged Caller Can Permanently Suppress Block Reward Distribution via `update_rewards` - (File: src/staking/staking.cairo)

### Summary
Any non-zero address can call `update_rewards` on the staking contract with `disable_rewards: true`, consuming the per-block reward slot and permanently preventing reward distribution for that block. Because `last_reward_block` is a global, single-slot counter updated before the `disable_rewards` guard, one attacker transaction per block is sufficient to zero out all staker and pool rewards for that block.

### Finding Description
`IStakingRewardsManager::update_rewards` is a public, permissionless function. Its only gate is `general_prerequisites()`, which checks that the contract is not paused and that the caller is not the zero address. [1](#0-0) 

Inside the function, `last_reward_block` is written to storage **before** the `disable_rewards` branch is evaluated: [2](#0-1) 

If `disable_rewards` is `true`, the function returns immediately after that write, skipping all reward calculation and distribution: [3](#0-2) 

Because `last_reward_block` is a single global value shared across all stakers, any subsequent call to `update_rewards` for the same block number will revert on the guard: [4](#0-3) 

The rewards that would have been minted and distributed for that block are permanently unclaimable — the reward supplier is never notified, no staker's `unclaimed_rewards_own` is incremented, and no pool receives its share. [5](#0-4) 

### Impact Explanation
Every block in the consensus-rewards phase generates STRK (and BTC) rewards for stakers and their delegation pools. An attacker who front-runs the legitimate `update_rewards` call each block with `disable_rewards: true` causes those rewards to be permanently lost — they are never claimed from the reward supplier and never credited to any staker or pool member. This constitutes **permanent freezing of unclaimed yield** (High).

### Likelihood Explanation
The attack requires only a valid, active staker address (all staker addresses are public on-chain) and a gas payment per block. No capital, no privileged key, and no protocol knowledge beyond the public ABI is needed. An attacker can automate this with a simple bot. Likelihood: **Medium** (economically irrational for a single attacker but feasible as a targeted griefing campaign against the protocol or a specific staker).

### Recommendation
Restrict `update_rewards` to a trusted caller — either the attestation contract, a dedicated consensus contract, or a new `REWARDS_MANAGER` role. Add an access-control assertion analogous to `assert_caller_is_attestation_contract` at the top of the function, before any state is written.

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_consensus_contract(); // or equivalent role check
    ...
```

Alternatively, if the function must remain permissionless, move the `last_reward_block` write to **after** the `disable_rewards` guard so that a no-op call does not consume the block slot.

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and the current epoch has passed it).
2. A new block `N` is produced.
3. Attacker calls:
   ```
   staking_contract.update_rewards(
       staker_address = <any active staker>,
       disable_rewards = true
   )
   ```
4. Inside the function:
   - `current_block_number (N) > last_reward_block` → passes.
   - `last_reward_block` is written to `N`.
   - `disable_rewards == true` → function returns immediately.
5. The legitimate consensus caller (or any staker) now calls `update_rewards` for block `N`:
   - `current_block_number (N) > last_reward_block (N)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers and pool members receive zero rewards for block `N`. The reward supplier retains the funds but they are never attributed to anyone.
7. Repeat for every block to suppress all consensus-phase rewards indefinitely.

### Citations

**File:** src/staking/staking.cairo (L1448-1460)
```text
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

**File:** src/staking/staking.cairo (L2348-2376)
```text
            // Update reward supplier.
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

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
            // Emit event.
            self
                .emit(
                    Events::StakerRewardsUpdated {
                        staker_address, staker_rewards, pool_rewards: pool_rewards_list.span(),
                    },
                );

            // Write staker rewards to storage.
            self.write_staker_info(:staker_address, :staker_info);
        }
```
