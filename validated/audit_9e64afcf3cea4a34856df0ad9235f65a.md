### Title
Any caller can invoke `update_rewards` with `disable_rewards: true` to silently skip block reward distribution while consuming the per-block reward slot — (File: src/staking/staking.cairo)

---

### Summary

`update_rewards` is a publicly callable function with no access control. It accepts a `disable_rewards: bool` parameter. When called with `disable_rewards: true`, the function writes the current block number to the global `last_reward_block` storage slot **before** checking the flag, then silently returns without distributing any rewards. Because `last_reward_block` is a single global value and the function enforces one call per block, an attacker who calls `update_rewards(any_valid_staker, true)` at block N permanently consumes the reward slot for block N for every staker in the protocol.

---

### Finding Description

In `src/staking/staking.cairo`, `StakingRewardsManagerImpl::update_rewards` is embedded as a public ABI entry point with no role check:

```cairo
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
``` [1](#0-0) 

The function first asserts the current block is strictly greater than `last_reward_block`, then **unconditionally writes** the current block number to `last_reward_block`, and only afterwards checks `disable_rewards`:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [2](#0-1) 

`last_reward_block` is a single global storage slot, not per-staker:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [3](#0-2) 

The guard that prevents double-calling is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [4](#0-3) 

Because the write happens before the `disable_rewards` branch, any subsequent legitimate call to `update_rewards` at the same block number will revert with `REWARDS_ALREADY_UPDATED`. The reward slot for that block is permanently consumed with zero rewards distributed.

The analog to the reported `PairInfos.sol` pattern is exact: a conditional check (`if disable_rewards`) silently skips the critical state update (reward distribution) while the surrounding state (`last_reward_block`) is already mutated, leaving the protocol in an inconsistent state with no revert and no signal to the legitimate caller.

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_staker_address, true)` once per block. Each such call:

1. Marks block N as "rewards already updated" globally.
2. Distributes zero rewards to any staker for block N.
3. Causes every subsequent legitimate `update_rewards` call at block N to revert.

Because `last_reward_block` is global, a single call per block is sufficient to deny block rewards to **all** stakers in the protocol for that block. Sustained over time this constitutes permanent freezing of unclaimed yield. Even a single call causes irreversible loss of one block's worth of rewards for every staker.

**Matched allowed impact**: *Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds* (High) / *Griefing with no profit motive but damage to users or protocol* (Medium).

---

### Likelihood Explanation

- `update_rewards` is a public ABI function with no role restriction.
- The only precondition is that `staker_address` must be a currently active staker with non-zero STRK balance — trivially satisfiable by observing any live staker on-chain.
- The attacker pays only gas per block. On Starknet, transaction fees are low enough to make sustained griefing economically viable.
- No special knowledge, leaked keys, or privileged access is required.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` guard, so that a call with `disable_rewards: true` does not consume the per-block reward slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);

// ... reward distribution logic ...
```

Alternatively, restrict `update_rewards` so that only the staker themselves (or a designated keeper) can call it for a given `staker_address`, preventing third-party abuse of the `disable_rewards` flag.

---

### Proof of Concept

1. Observe any active staker address `S` with non-zero STRK balance on-chain.
2. At block N (post-consensus, `is_pre_consensus()` returns false), submit:
   ```
   staking_contract.update_rewards(staker_address=S, disable_rewards=true)
   ```
3. `last_reward_block` is now set to N; no rewards are distributed.
4. The legitimate staker (or keeper) attempts:
   ```
   staking_contract.update_rewards(staker_address=S, disable_rewards=false)
   ```
   This reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat step 2 at block N+1, N+2, … to permanently deny all block rewards to all stakers.

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

**File:** src/staking/staking.cairo (L1454-1458)
```text
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
