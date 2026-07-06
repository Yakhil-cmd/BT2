### Title
Missing Caller Validation in `update_rewards()` Allows Anyone to Permanently Deny Block Rewards to All Stakers — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards()` function in the `Staking` contract has no check on who may call it. Because `last_reward_block` is a single global variable that is written on every call, an unprivileged attacker can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block to consume the block's reward slot without distributing any rewards, permanently denying block rewards to every staker for that block.

---

### Finding Description

`update_rewards` is exposed in the public ABI via `StakingRewardsManagerImpl` (`#[abi(embed_v0)]`). Its only access guard is `general_prerequisites()`, which checks two things: [1](#0-0) 

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

There is **no check** that the caller is the staker, the staker's operational address, or any other authorised entity.

Inside `update_rewards`, the very first thing that happens after the staker-existence checks is an unconditional write to the global `last_reward_block`: [2](#0-1) 

```cairo
let current_block_number = starknet::get_block_number();
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
// ...
self.last_reward_block.write(current_block_number);   // ← global write

if disable_rewards || self.is_pre_consensus() {
    return;   // ← exits without distributing rewards
}
```

Because `last_reward_block` is a **single contract-wide variable**, once it is written for block `N`, every subsequent call to `update_rewards` in block `N` reverts with `REWARDS_ALREADY_UPDATED`. The attacker therefore needs only **one transaction per block** to block the entire protocol from distributing consensus block rewards.

**Attack path:**

1. Attacker picks any currently-active staker address (all are public via `get_stakers()`).
2. At the start of each block, attacker calls `update_rewards(victim_staker, disable_rewards: true)`.
3. `last_reward_block` is updated to the current block; the function returns early — no rewards are distributed.
4. When the legitimate staker (or anyone else) tries to call `update_rewards` for the same block, the call reverts with `REWARDS_ALREADY_UPDATED`.
5. Block rewards for that block are permanently lost for **all** stakers, because the slot can never be reclaimed.

The attacker needs only a valid, active staker address with non-zero balance to pass the staker-existence assertions: [3](#0-2) 

---

### Impact Explanation

This is a **permanent, protocol-wide freezing of unclaimed yield** (consensus block rewards) for every staker. Each block for which the attacker fires the transaction is a block whose rewards are irrecoverably lost. Sustained over many blocks, this constitutes continuous theft/denial of unclaimed yield for all stakers.

Matches allowed impact: **High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

- The function is publicly callable with no special role or token balance required.
- The only input needed is any valid staker address, which is trivially obtained from on-chain events or `get_stakers()`.
- On Starknet, transaction fees are low, making a per-block griefing campaign economically feasible for a motivated attacker.
- The attacker gains nothing financially, but the damage to stakers is real and continuous.

---

### Recommendation

Add a caller-identity check to `update_rewards`. The caller should be restricted to the staker's registered operational address (or the staker address itself), mirroring the pattern used in `attest()` in `attestation.cairo`: [4](#0-3) 

Concretely, at the top of `update_rewards`, assert that `get_caller_address()` equals the operational address mapped to `staker_address` (via `operational_address_to_staker_address`), or the staker address itself. This ensures only the staker's own infrastructure can trigger reward updates, eliminating the griefing vector entirely.

---

### Proof of Concept

```
// Anyone can call this — no role or ownership check
staking_contract.update_rewards(
    staker_address: any_active_staker,  // publicly known
    disable_rewards: true,              // skip reward distribution
);
// last_reward_block is now set to current block.
// All subsequent calls this block revert with REWARDS_ALREADY_UPDATED.
// Block rewards are permanently lost for every staker.
```

Repeat once per block to continuously deny all consensus block rewards across the entire protocol.

### Citations

**File:** src/staking/staking.cairo (L1453-1489)
```text
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/attestation/attestation.cairo (L116-134)
```text
        fn attest(ref self: ContractState, block_hash: felt252) {
            let operational_address = get_caller_address();
            let staking_dispatcher = IStakingAttestationDispatcher {
                contract_address: self.staking_contract.read(),
            };
            // Note: This function checks for a zero staker address and will panic if so.
            let staking_attestation_info = staking_dispatcher
                .get_attestation_info_by_operational_address(:operational_address);
            self._validate_attestation(:block_hash, :staking_attestation_info);
            // Work is one tx per epoch.
            self
                ._mark_attestation_is_done(
                    staker_address: staking_attestation_info.staker_address(),
                    current_epoch: staking_attestation_info.epoch_id(),
                );
            staking_dispatcher
                .update_rewards_from_attestation_contract(
                    staker_address: staking_attestation_info.staker_address(),
                );
```
