### Title
Unrestricted `update_rewards` with `disable_rewards=true` Allows Any Caller to Permanently Block Reward Accrual for All Stakers - (File: src/staking/staking.cairo)

---

### Summary
`IStakingRewardsManager::update_rewards` is a public, permissionless function that accepts a caller-controlled `disable_rewards: bool` flag. Any anonymous address can call it with `disable_rewards: true`, which advances the global `last_reward_block` to the current block without distributing any rewards. Because the contract enforces a strict one-update-per-block invariant, every subsequent legitimate call in that block reverts with `REWARDS_ALREADY_UPDATED`. An attacker who repeats this every block permanently prevents all stakers from accumulating consensus-era block rewards.

---

### Finding Description

`update_rewards` is exposed as a public ABI entry point with no caller restriction beyond the generic `general_prerequisites()` check (not paused, caller not zero address). [1](#0-0) 

`general_prerequisites` enforces only two conditions: [2](#0-1) 

After validating that the supplied `staker_address` is active and has non-zero balance, the function unconditionally writes the current block number into the global `last_reward_block` storage slot: [3](#0-2) 

The one-update-per-block guard is checked at the top of the function: [4](#0-3) 

`last_reward_block` is a single global variable shared across all stakers: [5](#0-4) 

When `disable_rewards: true` is passed, the function returns immediately after writing `last_reward_block`, skipping all reward calculation and distribution: [6](#0-5) 

The attacker's call sequence per block:
1. Call `update_rewards(any_valid_staker, disable_rewards: true)`.
2. `last_reward_block` is set to the current block; no rewards are distributed.
3. Any legitimate call to `update_rewards` in the same block fails with `REWARDS_ALREADY_UPDATED`.
4. All stakers lose their block reward for that block.

Valid staker addresses are trivially discoverable from on-chain `NewStaker` events.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

In the consensus-rewards era (`is_pre_consensus() == false`), block rewards are the sole mechanism by which stakers accumulate `unclaimed_rewards_own`. By consuming the single per-block update slot with a no-op call every block, an attacker permanently prevents every staker from ever receiving block rewards. The yield is not merely delayed; it is never credited, because the block that was skipped cannot be retroactively replayed.

---

### Likelihood Explanation

**High.** The attack requires:
- A non-zero Starknet account (no stake, no role).
- A valid active staker address (publicly emitted in `NewStaker` events).
- One transaction per block.

Starknet transaction fees are low. The attacker has no requirement for capital, privileged access, or any external dependency. The attack is fully permissionless and can be automated with a simple bot.

---

### Recommendation

Restrict `update_rewards` to a trusted caller. The most natural restriction is to require the caller to be the staker's registered `operational_address` (consistent with the attestation flow), or alternatively the staker address itself. A secondary mitigation is to remove the `disable_rewards` parameter from the public interface entirely and handle that logic internally.

---

### Proof of Concept

```
// Attacker bot, runs once per block:
// 1. Read any active staker address S from NewStaker events.
// 2. Invoke:
staking_contract.update_rewards(
    staker_address: S,
    disable_rewards: true   // <-- attacker-controlled flag
);
// Result:
//   - last_reward_block = current_block  (no rewards distributed)
//   - All subsequent update_rewards calls this block revert with REWARDS_ALREADY_UPDATED
//   - Stakers earn zero block rewards for this block
// Repeat every block.
```

The only precondition is that `S` is an active staker with non-zero STRK balance at the current epoch, which is always satisfiable on a live network. The attacker spends only gas; stakers lose all consensus-era block rewards indefinitely.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1447-1452)
```text
    #[abi(embed_v0)]
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
