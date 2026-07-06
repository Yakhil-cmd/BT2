### Title
Unprivileged Caller Can Permanently Block Consensus Reward Distribution via `update_rewards(disable_rewards=true)` - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in `Staking.cairo` has no access control beyond `general_prerequisites()` (which only checks pause state and non-zero caller). Any unprivileged address can call it with `disable_rewards=true`, which advances the global `last_reward_block` checkpoint without distributing any rewards. Because `last_reward_block` is a single global variable, this permanently blocks reward distribution for that block for every staker in the protocol.

### Finding Description

`update_rewards` is exposed as a public function under `IStakingRewardsManager`: [1](#0-0) 

The only gate is `general_prerequisites()`: [2](#0-1) 

Which only checks pause state and non-zero caller — no role check, no attestation-contract-only guard.

Inside the function, `last_reward_block` is written **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

`last_reward_block` is a single global storage slot: [4](#0-3) 

The guard at the top of the function prevents any second call in the same block: [5](#0-4) 

**Attack path:**

1. At block `N`, attacker calls `update_rewards(any_active_staker, disable_rewards=true)`.
2. The function passes all checks (contract not paused, staker active, non-zero balance).
3. `last_reward_block` is set to `N`.
4. Execution returns early — no rewards are calculated or distributed.
5. Any subsequent call to `update_rewards` at block `N` reverts with `REWARDS_ALREADY_UPDATED`.
6. Rewards for block `N` are permanently lost for all stakers.
7. The attacker repeats this every block, continuously suppressing all consensus-phase reward distribution.

### Impact Explanation

Consensus rewards are calculated and distributed only once per block via `_update_rewards`, which accumulates `unclaimed_rewards_own` for the staker and transfers pool rewards to delegation pool contracts: [6](#0-5) 

When `disable_rewards=true` causes an early return, none of this happens. The rewards that would have been minted and distributed are permanently foregone — they are never added to `unclaimed_rewards_own` and never transferred to pools. This constitutes **permanent freezing of unclaimed yield** for all stakers and all pool members for every block the attacker targets.

### Likelihood Explanation

The call requires no special role, no stake, and no prior setup. Any EOA or contract can execute it. The only cost is gas. An attacker can automate this with a simple bot that calls `update_rewards(victim_staker, true)` at every block. The attack is profitable for a competitor staker who wants to suppress rivals' rewards, or for a griever with no profit motive.

### Recommendation

Add an access-control check to `update_rewards` so that only the attestation contract (or another designated privileged caller) can invoke it. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_attestation_contract(); // add this guard
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and let the attestation contract control reward eligibility through its own gated entry point (`update_rewards_from_attestation_contract`).

### Proof of Concept

```
Block N:
  Attacker calls: staking.update_rewards(staker=Alice, disable_rewards=true)
    → general_prerequisites() passes (not paused, caller != 0)
    → current_block_number (N) > last_reward_block → passes
    → staker Alice is active with non-zero balance → passes
    → last_reward_block.write(N)          ← block marked as consumed
    → disable_rewards == true → early return, zero rewards distributed

  Legitimate caller (attestation contract) calls: staking.update_rewards(staker=Alice, disable_rewards=false)
    → current_block_number (N) > last_reward_block (N) → FALSE → REVERT: REWARDS_ALREADY_UPDATED

  Alice's unclaimed_rewards_own: unchanged (0 added)
  Pool members' cumulative_rewards_trace: unchanged (0 added)
  Rewards for block N: permanently lost.

Attacker repeats every block → all consensus rewards permanently suppressed.
```

### Citations

**File:** src/staking/staking.cairo (L187-187)
```text
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1448-1452)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
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

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
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
