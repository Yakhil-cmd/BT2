### Title
Unrestricted `update_rewards` with `disable_rewards=true` Permanently Blocks Consensus Reward Distribution - (File: `src/staking/staking.cairo`)

---

### Summary

The `IStakingRewardsManager::update_rewards` function is publicly callable by any address and accepts a `disable_rewards` boolean. The global `last_reward_block` checkpoint is written **before** the `disable_rewards` guard, so an unprivileged attacker can call `update_rewards(valid_staker, true)` every block, consuming the per-block reward slot without distributing any rewards and blocking every legitimate call for that block.

---

### Finding Description

`update_rewards` is exposed as a public ABI function with no caller restriction beyond the generic `general_prerequisites()` (unpaused + non-zero caller). [1](#0-0) 

Inside the function, `last_reward_block` is written to storage **before** the `disable_rewards` branch: [2](#0-1) 

The guard that skips reward distribution comes only after: [3](#0-2) 

The assertion that enforces one call per block reads: [4](#0-3) 

Because `last_reward_block` is a single global storage slot shared across all stakers: [5](#0-4) 

the following attack loop is possible:

1. At block N, attacker calls `update_rewards(any_valid_staker, disable_rewards: true)`.
2. `last_reward_block` is set to N; the function returns early — no rewards distributed.
3. Any legitimate call at block N reverts with `REWARDS_ALREADY_UPDATED`.
4. Attacker repeats at block N+1, N+2, …

Valid staker addresses are fully public (emitted in `NewStaker` events), so the attacker has no barrier to supplying a valid `staker_address`.

The interface definition confirms there is no access-control annotation: [6](#0-5) 

---

### Impact Explanation

Every block of consensus rewards for every staker is permanently suppressed for as long as the attacker continues. Because `last_reward_block` is global, a single attacker call per block is sufficient to deny rewards to the entire staker set. This constitutes **temporary (and practically indefinite) freezing of unclaimed yield** — matching the allowed High impact: *Temporary freezing of funds / Permanent freezing of unclaimed yield*.

---

### Likelihood Explanation

High. The function is part of the public ABI with no role check. Starknet transaction fees are low, making a per-block griefing campaign economically viable. The attacker needs only one valid staker address, which is trivially obtained from on-chain events.

---

### Recommendation

Either:

1. **Restrict the caller**: Add an access-control check so only the designated consensus/attestation contract (or a whitelisted operator) may call `update_rewards`.
2. **Reorder the write**: Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so a call with `disable_rewards = true` does not consume the block's reward slot.

Option 2 is the minimal fix and preserves the existing call semantics for the consensus mechanism.

---

### Proof of Concept

```
// Pseudocode — repeat every block after consensus rewards start
loop {
    staking_contract.update_rewards(
        staker_address = <any active staker>,
        disable_rewards = true,
    );
    // last_reward_block = current_block; no rewards distributed
    // All legitimate update_rewards calls this block now revert with REWARDS_ALREADY_UPDATED
    wait_for_next_block();
}
```

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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
