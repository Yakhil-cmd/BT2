### Title
Unprivileged Caller Can Permanently Deny Block Rewards via `update_rewards(disable_rewards: true)` — (File: `src/staking/staking.cairo`)

---

### Summary

The `IStakingRewardsManager::update_rewards` function is callable by any unprivileged address and accepts a caller-controlled `disable_rewards: bool` parameter. When called with `disable_rewards: true`, the function writes the current block number into the global `last_reward_block` storage slot **before** the early-return guard, permanently consuming the reward slot for that block without distributing any rewards. Because `last_reward_block` is a single global variable, one such call per block silently denies consensus block rewards to every staker for that block.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role or ownership check is performed. [1](#0-0) 

The function then validates the staker and, critically, **writes `current_block_number` into `last_reward_block` unconditionally**, before the `disable_rewards` branch: [2](#0-1) 

After that write, the early-return fires when `disable_rewards` is `true`, skipping all reward calculation and distribution: [3](#0-2) 

`last_reward_block` is a single global slot shared across all stakers: [4](#0-3) 

The guard at the top of the function prevents a second call in the same block: [5](#0-4) 

Consequently, one attacker call per block with `disable_rewards: true` permanently exhausts the reward slot for that block for **all** stakers. The rewards that would have been minted and distributed are irrecoverably lost.

The `general_prerequisites` helper confirms there is no caller restriction beyond a zero-address check: [6](#0-5) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Each block in the consensus-rewards regime produces a fixed STRK (and BTC) reward that is split among all active stakers proportionally. By calling `update_rewards(any_valid_staker, disable_rewards: true)` once per block, an attacker causes `last_reward_block` to advance without any rewards being credited. Because the slot cannot be revisited, the yield for every affected block is permanently destroyed. Sustained over many blocks this amounts to total denial of consensus rewards across the entire protocol.

---

### Likelihood Explanation

**High.**

- No privileged role, token balance, or prior state is required.
- Any non-zero address can call the function.
- Valid staker addresses are publicly observable from on-chain events (`NewStaker`).
- The cost is one transaction per block; the attacker gains nothing but the damage to stakers is permanent.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` guard, so that a call with `disable_rewards: true` does not consume the block's reward slot:

```cairo
// Update last block rewards only when rewards are actually distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
// ... reward calculation continues
```

Alternatively, restrict `update_rewards` with an access-control check (e.g., only the staker or a designated keeper may call it with `disable_rewards: true`).

---

### Proof of Concept

```
// Attacker (any non-zero EOA or contract) executes once per block:
staking.update_rewards(
    staker_address: <any valid active staker>,
    disable_rewards: true,
);
// Result:
//   last_reward_block = current_block_number   (slot consumed)
//   no rewards credited to any staker
//   subsequent calls in this block revert with REWARDS_ALREADY_UPDATED
// Repeat every block → all consensus block rewards permanently denied.
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
