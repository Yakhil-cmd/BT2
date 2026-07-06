### Title
Global `last_reward_block` Updated Before `disable_rewards` Guard Enables Permanent Yield Freeze - (`src/staking/staking.cairo`)

---

### Summary

The publicly callable `update_rewards` function writes to the global `last_reward_block` storage variable **before** checking the `disable_rewards` flag. Because the function has no access control beyond `general_prerequisites()`, any unprivileged caller can invoke `update_rewards(valid_staker, disable_rewards: true)` in every block, consuming the block's single reward-distribution slot without distributing any rewards. This permanently freezes all consensus-phase yield for every staker in the protocol.

---

### Finding Description

`update_rewards` in `src/staking/staking.cairo` is the sole mechanism for distributing per-block consensus rewards (V3 phase). The function enforces a global one-call-per-block invariant via `last_reward_block`:

```cairo
// line 1454-1458
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

After validating the staker, the function unconditionally commits the current block number to storage:

```cairo
// line 1485
self.last_reward_block.write(current_block_number);
```

Only **after** this write does the function check whether rewards should actually be distributed:

```cairo
// line 1487-1489
if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [1](#0-0) 

Because `update_rewards` is `#[abi(embed_v0)]` with no role guard, any address can call it. Passing `disable_rewards: true` causes `last_reward_block` to advance to the current block while the reward-distribution logic is skipped entirely. Any subsequent legitimate call in the same block fails with `REWARDS_ALREADY_UPDATED`. [2](#0-1) 

The `last_reward_block` field is a single global value, not per-staker: [3](#0-2) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

In the consensus rewards phase (`is_pre_consensus() == false`), every block that a staker's `update_rewards` is not called with `disable_rewards: false` is a block of yield permanently lost — the reward supplier is never notified and the unclaimed rewards are never minted. An attacker who calls `update_rewards(any_valid_staker, true)` in every block prevents the entire protocol from ever distributing consensus rewards. The rewards are not deferred; they are simply never claimed from the reward supplier. [4](#0-3) 

---

### Likelihood Explanation

**High.** The attack requires:
1. Knowledge of any valid, active staker address (all staker addresses are public on-chain via the `stakers` vector and emitted events).
2. A single transaction per block with no token deposit, no stake, and no privileged role — only gas.

The `general_prerequisites()` check only asserts the contract is unpaused and the caller is non-zero. [5](#0-4) 

---

### Recommendation

Move `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so that a call with `disable_rewards: true` does not consume the block's reward slot:

```cairo
// Update last block rewards only when rewards are actually distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
// ... reward distribution logic ...
```

Alternatively, restrict who may pass `disable_rewards: true` (e.g., only the staker themselves or a privileged role), or remove the parameter entirely and handle the skip-rewards case through a separate privileged function.

---

### Proof of Concept

```
Precondition: consensus_rewards_first_epoch has been set and current_epoch >= it.

1. Attacker identifies any valid staker address S (e.g., from NewStaker events).
2. Each block N:
     attacker calls: staking.update_rewards(S, disable_rewards=true)
     → last_reward_block is written to N
     → function returns early, no rewards distributed
3. Any legitimate call staking.update_rewards(S', false) in block N:
     → asserts current_block_number > last_reward_block  (N > N)  → FAILS
4. Result: zero consensus rewards are ever distributed to any staker.
   All per-block yield is permanently lost.
``` [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1392-1395)
```text
    #[abi(embed_v0)]
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2348-2360)
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
```
