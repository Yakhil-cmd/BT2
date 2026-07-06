### Title
Unrestricted `update_rewards` with `disable_rewards: true` Permanently Denies Block Rewards to Stakers — (`src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract has no access control and accepts a caller-controlled `disable_rewards` boolean. Because a single global `last_reward_block` variable gates all reward updates to one call per block, any attacker can call `update_rewards(victim_staker, disable_rewards: true)` before the legitimate block proposer, consuming the per-block slot without distributing rewards. The block proposer's subsequent call reverts with `REWARDS_ALREADY_UPDATED`, and the rewards for that block are permanently lost.

---

### Finding Description

`update_rewards` is exposed on the public `IStakingRewardsManager` interface with no role check beyond `general_prerequisites()` (which only enforces pause state and non-zero caller):

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause + zero addr
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // consumed BEFORE reward check

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits with no rewards paid
    }
    ...
```

The critical sequence:

1. `last_reward_block` is written to `current_block_number` **unconditionally**, before the `disable_rewards` branch.
2. If `disable_rewards == true`, the function returns immediately — no rewards are distributed.
3. The global `last_reward_block` is now equal to the current block, so every subsequent call in the same block fails the `current_block_number > last_reward_block` assertion.

An attacker who submits `update_rewards(any_active_staker, true)` with higher gas priority than the legitimate block proposer's `update_rewards(proposer, false)` call will:

- Consume the single per-block slot.
- Distribute zero rewards.
- Cause the proposer's transaction to revert.
- Permanently erase the proposer's entitlement to that block's rewards (there is no retroactive recovery path).

The attacker needs no stake, no special role, and no capital beyond transaction gas.

---

### Impact Explanation

Each block's rewards that are skipped via this attack are **permanently unrecoverable** — the staker cannot retroactively claim rewards for a block whose `last_reward_block` slot was already consumed. Repeated execution across consecutive blocks constitutes a permanent, targeted denial of unclaimed yield.

This maps to the allowed impact: **Permanent freezing of unclaimed yield** (High).

---

### Likelihood Explanation

- The function is fully public; no stake, governance role, or privileged key is required.
- The attacker's only cost is gas for one transaction per block.
- Front-running is straightforward on Starknet (priority fee ordering).
- The attack is sustainable indefinitely at low cost.

---

### Recommendation

1. **Restrict the caller**: Only allow the staker themselves (or their registered `operational_address`) to call `update_rewards` for a given `staker_address`. Add a check such as:
   ```cairo
   let caller = get_caller_address();
   assert!(
       caller == staker_address || caller == staker_info.operational_address,
       "{}",
       Error::UNAUTHORIZED_CALLER,
   );
   ```
2. **Remove or gate `disable_rewards`**: If the pre-consensus use-case requires skipping reward distribution, handle it internally via `is_pre_consensus()` rather than exposing a caller-controlled bypass flag.
3. **Consider per-staker `last_reward_block`**: A global slot means one call blocks all stakers. A per-staker mapping would limit blast radius even if access control is not added.

---

### Proof of Concept

```
Block N:
  Attacker tx (high gas):  update_rewards(alice_staker_address, disable_rewards=true)
    → last_reward_block written to N
    → no rewards distributed
    → returns

  Alice's tx (lower gas):  update_rewards(alice_staker_address, disable_rewards=false)
    → assert!(N > N) → FAILS with REWARDS_ALREADY_UPDATED
    → Alice's block-N rewards are permanently lost
```

Attacker repeats this every block. Alice never receives consensus block rewards.

---

**Relevant code locations:**

`update_rewards` public entry point with no access control: [1](#0-0) 

`last_reward_block` written before `disable_rewards` check: [2](#0-1) 

`disable_rewards` branch that exits without distributing rewards: [3](#0-2) 

`general_prerequisites` — the only guard, which does not check caller identity: [4](#0-3) 

Interface declaration confirming no role restriction: [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1449-1456)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
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
