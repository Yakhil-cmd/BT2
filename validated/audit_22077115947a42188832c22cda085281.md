### Title
Permissionless `update_rewards` with `disable_rewards: true` Consumes the Per-Block Reward Slot, Blocking All Staker Reward Distribution - (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is callable by any address without access control. It accepts a `disable_rewards: bool` parameter. When called with `disable_rewards: true`, it writes the current block number to the global `last_reward_block` storage variable but skips reward distribution entirely. Because the function enforces a strict "once per block" constraint via `last_reward_block`, any subsequent legitimate call in the same block reverts with `REWARDS_ALREADY_UPDATED`. An attacker can front-run every legitimate reward update to permanently suppress consensus reward distribution for all stakers.

---

### Finding Description

`update_rewards` is defined in `src/staking/staking.cairo` under `StakingRewardsManagerImpl`: [1](#0-0) 

The function flow is:

1. Calls `general_prerequisites()` — checks only for pause state, **no role check**.
2. Asserts `current_block_number > self.last_reward_block.read()` — enforces once-per-block.
3. Validates the provided `staker_address` is active with non-zero balance.
4. **Writes `self.last_reward_block.write(current_block_number)`** — consuming the per-block slot.
5. If `disable_rewards == true` **or** `is_pre_consensus()`, returns immediately — **no rewards distributed**. [2](#0-1) 

The `last_reward_block` field is a **single global** storage variable, not per-staker: [3](#0-2) 

Once an attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` in block N, `last_reward_block` is set to N. Every subsequent call to `update_rewards` in block N — including the legitimate consensus mechanism call with `disable_rewards: false` — reverts with `REWARDS_ALREADY_UPDATED`. Because `last_reward_block` is global, this blocks reward distribution for **all** stakers in that block, not just the one passed as `staker_address`.

The `IStakingRewardsManager` interface confirms no access restriction is documented or enforced: [4](#0-3) 

Contrast this with genuinely privileged functions that explicitly call role checks (e.g., `pause` calls `self.roles.only_security_agent()`): [5](#0-4) 

`update_rewards` has no equivalent guard.

---

### Impact Explanation

**High — Permanent/ongoing freezing of unclaimed yield.**

An attacker can call `update_rewards(any_valid_staker, true)` once per block, every block, at negligible cost. Each such call:

- Consumes the global per-block reward slot.
- Prevents the legitimate consensus mechanism from distributing block rewards to any staker.
- Causes all stakers to permanently lose consensus-phase yield.

Because `last_reward_block` is global, a single attacker call per block is sufficient to freeze rewards for the entire protocol. The stakers' `unclaimed_rewards_own` fields are never incremented, and pool `cumulative_rewards_trace` entries are never updated, permanently denying yield to all participants.

---

### Likelihood Explanation

**High.** The function is permissionless — any EOA or contract can call it. The only precondition is supplying a valid, active staker address with non-zero balance, which is trivially obtained from on-chain events (`NewStaker`). The attack requires no capital, no privileged access, and no complex setup. Front-running a known per-block consensus call is straightforward on Starknet.

---

### Recommendation

Add access control to `update_rewards` so only an authorized role (e.g., a dedicated `REWARDS_MANAGER` role or the attestation contract) can invoke it. Alternatively, remove the `disable_rewards` parameter entirely and handle the "no rewards" case through a separate, access-controlled path, preventing any unprivileged caller from consuming the per-block slot with a no-op call.

---

### Proof of Concept

1. Staker Alice is active with non-zero STRK balance (address publicly known from `NewStaker` event).
2. Consensus rewards phase is active (`is_pre_consensus()` returns `false`).
3. In block N, the consensus mechanism prepares to call `update_rewards(alice, disable_rewards: false)`.
4. Attacker front-runs with `update_rewards(alice, disable_rewards: true)`:
   - `last_reward_block` is written to N.
   - Function returns early; no rewards distributed.
5. Consensus mechanism's call `update_rewards(alice, false)` in block N reverts: `REWARDS_ALREADY_UPDATED`.
6. No staker receives block rewards for block N.
7. Attacker repeats step 4 every block — all stakers are permanently denied consensus yield.

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1249-1257)
```text
    impl StakingPauseImpl of IStakingPause<ContractState> {
        fn pause(ref self: ContractState) {
            self.roles.only_security_agent();
            if self.is_paused() {
                return;
            }
            self.is_paused.write(true);
            self.emit(PauseEvents::Paused { account: get_caller_address() });
        }
```

**File:** src/staking/staking.cairo (L1448-1490)
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

```

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
