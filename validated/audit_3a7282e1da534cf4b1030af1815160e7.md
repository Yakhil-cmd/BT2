### Title
Missing Caller Access Control in `update_rewards` Allows Any Staker to Steal Per-Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the `Staking` contract is specified to be callable **only by the Starkware sequencer**, but the implementation contains **no on-chain caller check**. Because a single global `last_reward_block` lock prevents more than one call per block, any registered staker who calls `update_rewards` first in a given block directs the entire block's rewards to themselves, permanently denying those rewards to the staker the sequencer intended to reward.

---

### Finding Description

**Spec-mandated access control (never implemented):**

The specification at `docs/spec.md` lines 1644–1645 states:

> `update_rewards` — Access control: **Only starkware sequencer.** [1](#0-0) 

**Actual implementation — no caller check:**

`StakingRewardsManagerImpl::update_rewards` in `src/staking/staking.cairo` calls only `self.general_prerequisites()` (a pause check) and then immediately proceeds to validate the staker and distribute rewards. There is no `assert!(get_caller_address() == sequencer_address, ...)` or equivalent guard anywhere in the function body. [2](#0-1) 

**Global `last_reward_block` lock — winner-takes-all per block:**

The function writes `self.last_reward_block.write(current_block_number)` unconditionally after the first successful call. Any subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. This means whichever caller wins the race for a given block receives **all** of that block's rewards for their chosen `staker_address`; the sequencer's intended recipient is permanently locked out for that block. [3](#0-2) 

**Full block rewards flow to the caller-chosen staker:**

In the V3 (consensus) reward model, `strk_total_stake` passed to `_update_rewards` is the **caller-chosen staker's own total balance** (not the global total stake). Consequently `calculate_staker_own_rewards` computes `own_balance / staker_total_balance × block_rewards`, which sums to 100 % of `block_rewards` across the staker and their pools — the entire block reward is paid out to the attacker-chosen staker. [4](#0-3) 

**Test evidence confirming no access control:**

The unit test `test_update_rewards_only_staker` calls `update_rewards` directly from the test address (no `cheat_caller_address_once`) and succeeds, confirming the absence of any caller restriction. [5](#0-4) 

---

### Impact Explanation

**High — Theft of unclaimed yield + Permanent freezing of unclaimed yield.**

An attacker who is a registered staker can call `update_rewards(attacker_staker_address, disable_rewards: false)` before the sequencer's intended call. The attacker's staker receives the full block reward. The sequencer's subsequent call for the intended staker reverts with `REWARDS_ALREADY_UPDATED`, and that staker's block reward is **permanently lost** — there is no mechanism to retroactively credit a missed block.

---

### Likelihood Explanation

**Medium.** The attack requires the attacker's transaction to be included in the block before the sequencer's own `update_rewards` system call. On Starknet's current centralized sequencer this is non-trivial under normal operation, but becomes straightforward whenever:

- The sequencer experiences downtime or a bug and omits its own call for a block.
- The sequencer transitions toward decentralization and loses exclusive ordering control.
- The sequencer includes user transactions before its own system calls in any block.

The attacker needs only to be a registered staker (an unprivileged role) and to submit a valid `update_rewards` call.

---

### Recommendation

Add an explicit sequencer-address check at the top of `update_rewards`, analogous to the pattern already used for `update_unclaimed_rewards_from_staking_contract` and `claim_rewards` in the `RewardSupplier`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    self.general_prerequisites();
    // ...
}
```

Store the authorized sequencer address in contract storage and expose a governance-controlled setter, mirroring the `staking_contract` address pattern in `RewardSupplier`. [6](#0-5) 

---

### Proof of Concept

1. Staker A (attacker) and Staker B (legitimate, intended by sequencer) are both registered and active.
2. At block N, the sequencer is about to call `update_rewards(staker_B, disable_rewards: false)`.
3. Attacker submits `update_rewards(staker_A, disable_rewards: false)` and it is included first.
4. `last_reward_block` is set to N; Staker A receives the full block reward.
5. Sequencer's call for Staker B reverts: `REWARDS_ALREADY_UPDATED`.
6. Staker B's block-N reward is permanently lost; Staker A has stolen it.

The attack requires no privileged access — only a valid staker registration and the ability to submit a transaction that lands before the sequencer's own call. [7](#0-6)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1447-1507)
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

**File:** src/staking/tests/test.cairo (L3515-3516)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
```

**File:** src/reward_supplier/reward_supplier.cairo (L205-212)
```text
        fn claim_rewards(ref self: ContractState, amount: Amount) {
            // Asserts.
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
```
