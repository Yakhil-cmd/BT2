### Title
Unconstrained `staker_address` in `update_rewards` Creates Race Condition Allowing Reward Theft and Permanent Yield Freeze — (File: src/staking/staking.cairo)

---

### Summary

`update_rewards` in `staking.cairo` is callable by any non-zero address and accepts an arbitrary `staker_address` parameter. A single-slot guard (`last_reward_block`) ensures only one reward update per block, but because neither the caller nor the `staker_address` is validated against the actual block proposer, any actor can race to call the function first — either redirecting block rewards to an arbitrary staker or consuming the slot with `disable_rewards: true` to ensure no rewards are distributed at all.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero: [1](#0-0) 

The function then enforces a single-call-per-block invariant via `last_reward_block`: [2](#0-1) 

After writing `last_reward_block`, if `disable_rewards` is `true`, the function returns immediately without distributing any rewards: [3](#0-2) 

The `staker_address` parameter is only validated to be an existing, active staker with non-zero balance — there is no check that the caller is the staker, the staker's operational address, or the actual block proposer: [4](#0-3) 

This is structurally analogous to the external report: just as `isValidHash` allowed multiple bounties to be simultaneously valid (making the final state depend on call order), here multiple valid stakers are simultaneously eligible as the `staker_address` argument, and the first caller determines the final state — which staker receives block rewards, or whether any staker receives them at all.

---

### Impact Explanation

**Attack path 1 — Theft of unclaimed yield (High):**
A malicious actor who is also a registered staker can front-run the legitimate block proposer in every block by calling `update_rewards(attacker_staker_address, false)`. Because `last_reward_block` is updated on the first call, the legitimate proposer's subsequent call reverts with `REWARDS_ALREADY_UPDATED`. Block rewards are permanently redirected to the attacker's staker address.

**Attack path 2 — Permanent freezing of unclaimed yield (High):**
Any non-zero address (even one that is not a staker) can call `update_rewards(any_valid_staker, disable_rewards: true)` in every block. The slot is consumed, `last_reward_block` advances, and no rewards are distributed. Repeated across all blocks, this permanently prevents any staker from ever receiving consensus rewards.

Both impacts fall within the allowed scope: *Theft of unclaimed yield* and *Permanent freezing of unclaimed yield*.

---

### Likelihood Explanation

The entry path requires no privilege — only a non-zero caller address. On Starknet, transaction fees are low, making sustained block-by-block griefing economically viable. The attacker needs only to submit a transaction before the legitimate proposer in each block, which is straightforward given that `update_rewards` is a public, permissionless function.

---

### Recommendation

Restrict `update_rewards` so that only the staker themselves or their registered operational address can call it for a given `staker_address`. Concretely, add a check such as:

```cairo
let caller = get_caller_address();
assert!(
    caller == staker_address || caller == staker_info.operational_address,
    "{}",
    Error::UNAUTHORIZED_CALLER,
);
```

This mirrors the fix recommended in the external report: instead of allowing any caller to specify any valid entry, bind the call to a single authoritative identity (the staker or their operational address), eliminating the race condition.

---

### Proof of Concept

1. Staker A is the legitimate block proposer for block N and intends to call `update_rewards(staker_A, false)`.
2. Malicious actor M (any non-zero address) observes the mempool and front-runs with `update_rewards(staker_B, disable_rewards: true)` (attack path 2) or `update_rewards(staker_M, false)` (attack path 1).
3. M's transaction executes first: `last_reward_block` is set to N; no rewards are distributed (path 2) or rewards go to staker M (path 1).
4. Staker A's transaction reverts: `current_block_number > self.last_reward_block.read()` is false.
5. Staker A receives zero rewards for block N.
6. Repeating steps 2–5 for every block permanently freezes or redirects all consensus rewards. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1448-1507)
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
