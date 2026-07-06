### Title
Publicly Callable `update_rewards` with `disable_rewards: true` Permanently Freezes Consensus Yield — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `src/staking/staking.cairo` enforces a once-per-block reward update via the global `last_reward_block` storage variable. However, because `last_reward_block` is written **before** the `disable_rewards` guard is evaluated, any unprivileged caller can invoke `update_rewards(any_valid_staker, disable_rewards: true)` to consume the block's reward slot without distributing any yield. The consensus mechanism's legitimate call in the same block then fails with `REWARDS_ALREADY_UPDATED`, permanently suppressing reward accrual for all stakers.

---

### Finding Description

`update_rewards` is a public, permissionless entry point in `IStakingRewardsManager`:

```cairo
// src/staking/interface.cairo
pub trait IStakingRewardsManager<TContractState> {
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
``` [1](#0-0) 

The implementation in `staking.cairo` (lines 1448–1500) follows this order:

1. Assert `current_block_number > last_reward_block` — the once-per-block guard.
2. Validate the staker exists and has non-zero balance.
3. **Write `last_reward_block = current_block_number`** — the slot is consumed here.
4. `if disable_rewards || self.is_pre_consensus() { return; }` — early exit, no rewards distributed. [2](#0-1) 

Step 3 occurs unconditionally, before the `disable_rewards` branch. An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` in block N:

- Passes the guard (step 1).
- Writes `last_reward_block = N` (step 3).
- Returns immediately without distributing rewards (step 4).

Any subsequent call to `update_rewards` in block N — including the consensus mechanism's legitimate call — hits the assertion at step 1 and reverts with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

The function has no caller restriction beyond `general_prerequisites()`, which only checks the pause flag and zero-address.

---

### Impact Explanation

By repeating this call every block, an attacker permanently prevents consensus reward distribution for every staker in the protocol. Stakers' `unclaimed_rewards_own` fields never increase, and pool contracts never receive `update_rewards_from_staking_contract` calls. This constitutes **permanent freezing of unclaimed yield** for all protocol participants.

Impact category matched: **High — Permanent freezing of unclaimed yield or unclaimed royalties**.

---

### Likelihood Explanation

- The function is permissionless; no staking position or privileged role is required.
- The attacker only needs to supply any currently active staker address (publicly enumerable via the `stakers` vector in storage).
- The attack cost is one Starknet transaction per block. Starknet transaction fees are low, making sustained griefing economically viable.
- No front-running sophistication is needed; the attacker simply submits the call in each block before the consensus sequencer does.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` guard, so that a no-op call does not consume the block's reward slot:

```cairo
// Update last block rewards only when rewards will actually be distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
// ... distribute rewards ...
```

Alternatively, restrict `update_rewards` to a trusted caller (e.g., the consensus sequencer address stored in contract config), consistent with how `update_rewards_from_attestation_contract` is restricted to the attestation contract. [4](#0-3) 

---

### Proof of Concept

```
Block N:
  Attacker tx:  update_rewards(staker=<any_active_staker>, disable_rewards=true)
    → last_reward_block := N
    → returns (no rewards distributed)

  Consensus tx: update_rewards(staker=<correct_staker>, disable_rewards=false)
    → assert(N > N) FAILS → REWARDS_ALREADY_UPDATED

Block N+1:
  Attacker repeats → last_reward_block := N+1
  Consensus call fails again.

Result: unclaimed_rewards_own never increments for any staker.
        Pool contracts never receive reward updates.
        All yield is permanently frozen.
```

### Citations

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

**File:** src/staking/staking.cairo (L1392-1401)
```text
    #[abi(embed_v0)]
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

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
