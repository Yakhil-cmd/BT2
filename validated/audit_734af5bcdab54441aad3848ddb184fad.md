### Title
Unrestricted `disable_rewards` Flag in `update_rewards` Enables Permanent Griefing of All Stakers' Yield — (File: `src/staking/staking.cairo`)

---

### Summary
Any unprivileged caller can invoke `update_rewards` with `disable_rewards = true` to advance the global `last_reward_block` checkpoint without distributing any rewards. Because `last_reward_block` is a single contract-wide variable, this permanently blocks every staker from receiving consensus-mode block rewards for that block. Repeating the call every block permanently freezes yield accumulation for the entire protocol.

---

### Finding Description

`update_rewards` is a public function (part of `IStakingRewardsManager`, embedded via `#[abi(embed_v0)]`) that accepts a caller-controlled `disable_rewards: bool` parameter. The function unconditionally writes `current_block_number` to the global `last_reward_block` storage variable **before** checking `disable_rewards`: [1](#0-0) 

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
```

The guard at the top of the function prevents any second call in the same block: [2](#0-1) 

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

Because `last_reward_block` is a **single global variable** (not per-staker), any call to `update_rewards` in block N — regardless of `disable_rewards` — consumes the block's reward slot for every staker. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` every block permanently prevents any staker from accumulating consensus-mode block rewards.

The only access control is `general_prerequisites()`, which only checks that the contract is not paused and the caller is non-zero: [3](#0-2) 

No privileged role, no deposited capital, and no flash loan are required.

The analog to the original report is direct: in `Pool.sol`, a user could call `depositAndVote()` to set `dailyInterestRate_` to zero, exploit the zero-rate state, then call `withdraw()` — all because a user-controlled parameter nullified a locking invariant. Here, a user-controlled boolean parameter (`disable_rewards = true`) nullifies the reward-distribution invariant of the global `last_reward_block` checkpoint, allowing the attacker to "consume" every block's reward slot without distributing anything.

---

### Impact Explanation

In consensus rewards mode, `update_rewards` is the **sole mechanism** for distributing per-block rewards to stakers. By calling it with `disable_rewards = true` every block, an attacker can permanently freeze the accumulation of unclaimed yield for all stakers in the protocol. This matches the **High** impact category: *"Permanent freezing of unclaimed yield."*

---

### Likelihood Explanation

- No special role, no deposited capital, no flash loan required.
- Any non-zero EOA or contract can call `update_rewards`.
- The only cost is gas per block on Starknet, which is economically feasible for a motivated attacker (e.g., a competing protocol or a staker who wants to suppress rivals).
- The attack is fully deterministic and requires no coordination.

---

### Recommendation

1. **Remove `disable_rewards` from the public interface**, or gate it behind a privileged role (e.g., `only_security_agent`).
2. If `disable_rewards` is needed for migration, restrict it to a trusted internal caller (e.g., only callable by the contract itself or the governance admin).
3. Alternatively, make `last_reward_block` a per-staker variable so that one call cannot block all other stakers.

---

### Proof of Concept

1. Attacker identifies any valid, active staker address `

### Citations

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
