### Title
Unprivileged Caller Can Front-Run `update_rewards` With `disable_rewards: true` to Grief Per-Block Reward Distribution — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract has no access control and accepts a caller-controlled `disable_rewards` boolean. Because `last_reward_block` (a **global** state) is written **before** the `disable_rewards` check, any unprivileged caller can consume the per-block reward slot without distributing rewards. This prevents all legitimate `update_rewards` calls in the same block from succeeding, causing every staker to miss that block's consensus rewards.

---

### Finding Description

`update_rewards` is a public function with no role restriction beyond `general_prerequisites()` (unpaused + non-zero caller). [1](#0-0) 

The function first writes the current block number to the global `last_reward_block`: [2](#0-1) 

Only **after** that write does it check `disable_rewards`: [3](#0-2) 

Because `last_reward_block` is a **single global field** (not per-staker): [4](#0-3) 

…and the guard at the top of the function is: [5](#0-4) 

…once any caller writes `last_reward_block = block_N`, **no other call** to `update_rewards` can succeed in block N, regardless of which staker is targeted.

**Attack path:**

1. Attacker observes a pending `update_rewards(staker_X, disable_rewards: false)` transaction (or simply calls proactively at the start of every block).
2. Attacker submits `update_rewards(any_valid_staker, disable_rewards: true)` with higher priority / earlier in the block.
3. `last_reward_block` is set to the current block; the function returns early — **no rewards distributed**.
4. Every subsequent `update_rewards` call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers miss that block's consensus rewards.

The attacker needs no special role, no stake, and no funds beyond gas. The only requirement is knowing one valid, active staker address — which is publicly readable from the `stakers` vector. [6](#0-5) 

---

### Impact Explanation

Each successful attack silently drops one block's worth of consensus rewards for **all** stakers and their delegators. Repeated every block, this constitutes a **permanent freezing of unclaimed yield** for the entire protocol. Even a sporadic attack causes **temporary freezing of unclaimed yield**, which maps to the High impact tier in the allowed scope.

---

### Likelihood Explanation

The function is fully public with no access control. The attacker requires only:
- A valid staker address (publicly enumerable).
- Gas to call `update_rewards` once per block.

There is no economic barrier. A motivated griefer (e.g., a competing protocol, a slashed staker, or a censorship actor) can sustain this indefinitely at low cost.

---

### Recommendation

1. **Add access control** to `update_rewards`: restrict it to a trusted role (e.g., `only_app_governor` or a dedicated `REWARDS_UPDATER_ROLE`), consistent with the `IStakingRewardsManager` naming intent.
2. **Separate the `disable_rewards` path**: if skipping reward distribution is needed for protocol transitions, expose it as a separate privileged function rather than a caller-supplied flag in a public entry point.
3. At minimum, **move the `last_reward_block` write to after the `disable_rewards` guard**, so that a `disable_rewards: true` call does not consume the block slot.

---

### Proof of Concept

```
// Block N begins.

// Step 1 – Attacker front-runs with disable_rewards: true.
staking.update_rewards(staker_address: any_valid_staker, disable_rewards: true);
// → last_reward_block is now N; function returns early; no rewards distributed.

// Step 2 – Legitimate consensus caller tries to distribute rewards.
staking.update_rewards(staker_address: staker_X, disable_rewards: false);
// → Panics: "REWARDS_ALREADY_UPDATED"
// → All stakers miss block N's consensus rewards.
```

The root cause mirrors the external report exactly: a shared "nonce" (`last_reward_block`) is consumed by one call path (`disable_rewards: true`) before the intended call path (`disable_rewards: false`) can use it, causing the legitimate operation to revert and the protocol to lose the associated value (block rewards).

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1448-1460)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
