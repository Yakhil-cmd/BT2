### Title
Unprivileged Caller Can Permanently Freeze Per-Block Rewards for Any Staker via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function is publicly callable by any address and accepts a caller-controlled `disable_rewards: bool` parameter. A global `last_reward_block` lock enforces a single-call-per-block invariant. An attacker who calls `update_rewards(victim_staker, true)` in a given block consumes that block's single-call slot without distributing any rewards, permanently denying the victim staker their per-block yield for that block.

### Finding Description
In V3 consensus rewards mode, `update_rewards` is the mechanism by which a staker claims per-block rewards. The function enforces a single-call-per-block invariant via a **global** `last_reward_block` storage variable:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
...
self.last_reward_block.write(current_block_number);
```

After writing `last_reward_block`, the function checks the caller-supplied `disable_rewards` flag:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
```

When `disable_rewards = true`, the function returns early without distributing any rewards. Since `last_reward_block` is already set to the current block, no subsequent call to `update_rewards` can succeed in the same block — the assertion at the top will revert with `REWARDS_ALREADY_UPDATED`.

The function has no access control beyond `general_prerequisites()`, which only checks that the contract is unpaused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

Any non-zero address can call `update_rewards` for any `staker_address` with `disable_rewards: true`.

The relevant code path is: [1](#0-0) 

The `general_prerequisites` check: [2](#0-1) 

The `last_reward_block` write and early return: [3](#0-2) 

### Impact Explanation
An attacker calls `update_rewards(victim_staker_address, true)` in any block to:
1. Consume the single-call-per-block slot for that block (writing `last_reward_block = current_block`)
2. Return early without distributing any rewards to the victim staker

Since block rewards are per-block and non-recoverable — there is no mechanism to retroactively claim missed block rewards — this constitutes **permanent freezing of unclaimed yield** for the affected block. An attacker can repeat this every block, permanently denying all block rewards to a targeted staker. The staker's `unclaimed_rewards_own` is never incremented, and the pool's `cumulative_rewards_trace` is never updated for those blocks. [4](#0-3) 

### Likelihood Explanation
- The function is public with no meaningful access control
- The attack requires only a single transaction per block per targeted staker
- No capital, tokens, or special privileges are required
- In a decentralized sequencer environment (the target deployment context for this staking contract), front-running a specific staker's `update_rewards` call is straightforward — the attacker simply submits the same call with `disable_rewards: true` at a higher gas price or earlier in the block

### Recommendation
Add access control to `update_rewards` so that only the staker themselves (or an authorized caller such as the attestation contract or the block proposer mechanism) can invoke it. Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the disable logic through a separate privileged function. At minimum, the `disable_rewards = true` path should be restricted to a trusted role.

### Proof of Concept
1. Victim staker `S` is the block proposer for block `N` and intends to call `update_rewards(S, false)` to claim block rewards.
2. Attacker observes the pending transaction and front-runs it by calling `update_rewards(S, true)` in block `N`.
3. Inside `update_rewards`: `current_block_number (N) > last_reward_block` passes; `last_reward_block` is written to `N`; `disable_rewards = true` causes early return — no rewards distributed.
4. Staker `S` attempts to call `update_rewards(S, false)` in block `N` — reverts with `REWARDS_ALREADY_UPDATED` because `N > N` is false.
5. Staker `S` receives zero block rewards for block `N`; `unclaimed_rewards_own` is unchanged; pool `cumulative_rewards_trace` is not updated.
6. Attacker repeats every block, permanently denying all consensus block rewards to staker `S` at negligible cost. [5](#0-4)

### Citations

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
