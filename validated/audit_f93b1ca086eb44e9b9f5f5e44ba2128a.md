### Title
Unrestricted `update_rewards` with `disable_rewards: true` Allows Any Caller to Permanently Block Consensus Reward Distribution — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract carries no caller restriction. Any unprivileged address can call `update_rewards(staker_address, disable_rewards: true)` once per block to mark the global `last_reward_block` as current without distributing any rewards. Because `last_reward_block` is a single contract-wide variable, one such call per block is sufficient to starve **all** stakers of consensus block rewards indefinitely.

---

### Finding Description

**Normal reward path (pre-consensus / V2):** `update_rewards_from_attestation_contract` enforces two hard guards before touching rewards:

```
assert!(self.is_pre_consensus(), Error::CONSENSUS_REWARDS_IS_ACTIVE);
self.assert_caller_is_attestation_contract();
``` [1](#0-0) 

**Consensus reward path (V3):** `update_rewards` in `StakingRewardsManagerImpl` enforces only `general_prerequisites()` — a pause check and a non-zero-caller check — with no restriction on *who* the caller is and no restriction on the `disable_rewards` flag:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only: not paused + caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // ← consumes the slot
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits without rewards
    }
    ...
    self._update_rewards(...);
}
``` [2](#0-1) 

`last_reward_block` is a **single global** storage variable shared across all stakers:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [3](#0-2) 

`general_prerequisites` only checks pause state and non-zero caller — no identity or role check:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [4](#0-3) 

**The bypass:** Because `last_reward_block` is global and is written *before* the early-return branch, a single call to `update_rewards(any_active_staker, disable_rewards: true)` in block N:

1. Passes all checks (contract not paused, caller non-zero, block N > last recorded block).
2. Writes `last_reward_block = N`.
3. Returns immediately — zero rewards distributed.

Any subsequent legitimate call to `update_rewards(..., disable_rewards: false)` in the same block N reverts with `REWARDS_ALREADY_UPDATED`. The attacker must repeat this once per block to suppress rewards permanently.

This is structurally identical to the external report's finding: the bridge burn/remint path consumed the "one operation per flow" slot without executing the policy-engine hook, just as `update_rewards` with `disable_rewards: true` consumes the "one update per block" slot without executing the reward-distribution logic.

---

### Impact Explanation

An attacker calling `update_rewards(any_staker, disable_rewards: true)` in every block prevents **all** stakers from accumulating consensus block rewards. Because `last_reward_block` is global, a single call per block is sufficient to grief the entire protocol. Stakers' `unclaimed_rewards_own` fields never increase; pool members' cumulative reward traces are never updated. This constitutes **permanent freezing of unclaimed yield** for all stakers and pool members as long as the attack is sustained.

---

### Likelihood Explanation

The entry point is fully public — no role, no key, no privileged access required. The only cost is the gas for one Starknet transaction per block (~3 s block time). The attacker gains nothing financially but can sustain the attack indefinitely at low cost. Front-running is not required; the attacker simply needs to submit the transaction before any legitimate `update_rewards` call in each block.

---

### Recommendation

Add a caller restriction to `update_rewards` analogous to the one in `update_rewards_from_attestation_contract`. The simplest fix is to assert that the caller is the attestation contract (or a designated keeper role):

```cairo
self.assert_caller_is_attestation_contract();
```

Alternatively, remove the `disable_rewards` parameter entirely and derive the "no rewards" condition from on-chain state (e.g., whether the staker attested in the current epoch), so that the reward-distribution decision cannot be externally injected by an arbitrary caller.

---

### Proof of Concept

```
// Attacker script — runs once per block
loop {
    staking_contract.update_rewards(
        staker_address = any_active_staker,
        disable_rewards = true,   // ← skips _update_rewards, still writes last_reward_block
    );
    wait_for_next_block();
}

// Legitimate keeper — always reverts in the same block
staking_contract.update_rewards(
    staker_address = victim_staker,
    disable_rewards = false,
);
// → panics: "Rewards already updated for this block"
```

After sustained execution, every staker's `unclaimed_rewards_own` remains zero and every pool's `cumulative_rewards_trace` is never advanced, permanently freezing all unclaimed yield.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
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
