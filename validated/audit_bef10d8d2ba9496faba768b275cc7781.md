### Title
Unprivileged caller can permanently freeze all consensus rewards by calling `update_rewards` with `disable_rewards: true` every block — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract enforces a single-call-per-block invariant via the global `last_reward_block` storage variable. Because the function has no access control beyond a zero-address check, any unprivileged caller can invoke it with `disable_rewards: true` to consume the block's reward slot without distributing any rewards. Repeating this every block permanently prevents all stakers from earning consensus rewards.

---

### Finding Description

`update_rewards` is the entry point for distributing per-block consensus rewards (V3 regime). Its only gate is `general_prerequisites`, which checks that the contract is unpaused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

Inside `update_rewards`, the global `last_reward_block` is written **before** the `disable_rewards` branch is evaluated:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [2](#0-1) 

The guard at the top of the function enforces that only one call per block can proceed:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

`last_reward_block` is a single global variable shared across all stakers:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [4](#0-3) 

**Attack path:**
1. Attacker identifies any active staker with non-zero balance (public on-chain data).
2. In every block N, attacker calls `update_rewards(active_staker, disable_rewards: true)`.
3. `last_reward_block` is set to N; the function returns early — no rewards are distributed.
4. Any subsequent legitimate call to `update_rewards` in block N reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeating this every block permanently freezes all consensus reward distribution.

The attacker needs only to pay gas; no stake, no privileged role, no special setup is required.

---

### Impact Explanation

All stakers and their delegators are permanently denied consensus (block-based) rewards. Unclaimed yield that would have accrued via `_update_rewards` → `staker_info.unclaimed_rewards_own` and pool `cumulative_rewards_trace` updates is never credited. This constitutes **permanent freezing of unclaimed yield** for the entire protocol. [5](#0-4) 

---

### Likelihood Explanation

The attack requires no capital, no privileged access, and no coordination. Any EOA or contract can call `update_rewards` with an arbitrary `staker_address` and `disable_rewards: true`. The only cost is gas per block. On Starknet, gas costs are low, making sustained griefing economically viable. The attacker has no incentive to stop once started, as they suffer no loss.

---

### Recommendation

Add access control to `update_rewards` so that only a trusted caller (e.g., the sequencer, a designated rewards-manager role, or the staker themselves) can invoke it. At minimum, restrict the `disable_rewards: true` path to a privileged role. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    if disable_rewards {
        self.roles.only_rewards_manager(); // new role
    }
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle reward disabling through a separate privileged function.

---

### Proof of Concept

```
1. Deploy/use any active staker address S with non-zero STRK balance.
2. In every block B:
     call staking.update_rewards(S, disable_rewards=true)
     → last_reward_block is set to B
     → function returns early, no rewards distributed
3. Any legitimate call to update_rewards in block B now reverts:
     assert!(current_block_number > last_reward_block) → FAILS
4. After N blocks, all stakers have earned zero consensus rewards.
   staker_info.unclaimed_rewards_own remains 0 for all stakers.
   pool cumulative_rewards_trace is never updated.
```

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1454-1458)
```text
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

**File:** src/staking/staking.cairo (L2349-2376)
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
