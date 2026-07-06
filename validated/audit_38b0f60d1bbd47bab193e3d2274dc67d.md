### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Consensus Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract lacks any caller authorization check. The protocol specification explicitly designates this function as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged address can call `update_rewards(valid_staker, disable_rewards: true)` at each block, consuming the global `last_reward_block` slot without distributing rewards, permanently preventing the sequencer from distributing consensus rewards for that block.

### Finding Description
The `update_rewards` function uses a single global storage variable `last_reward_block` as a per-block gate. The check at line 1454–1458 asserts `current_block_number > self.last_reward_block.read()`, and the write at line 1485 sets `last_reward_block` to the current block number. This write occurs **before** the `disable_rewards` branch at line 1487, meaning a call with `disable_rewards: true` still consumes the block slot while distributing zero rewards.

The only caller validation is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero — no role or address check is performed. The protocol specification at `docs/spec.md` line 1645 states: **"Only starkware sequencer"** may call this function, but this invariant is not enforced in code.

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` at block N:
1. Passes all assertions (staker exists, is active, has non-zero balance).
2. Writes `last_reward_block = N`.
3. Returns early — no rewards distributed.
4. The sequencer's subsequent call at block N fails with `REWARDS_ALREADY_UPDATED`.

Rewards for block N are permanently lost; the sequencer cannot retroactively distribute them.

### Impact Explanation
If an attacker front-runs the sequencer at every block, all consensus-era block rewards are permanently frozen. Stakers and pool members accumulate zero `unclaimed_rewards_own` and zero pool balances despite the protocol being active. This constitutes **permanent freezing of unclaimed yield** (High impact). Even sporadic attacks cause irreversible per-block reward losses.

### Likelihood Explanation
The attack requires no privileged access — any EOA or contract can call `update_rewards`. The attacker must front-run the sequencer at each target block, which is feasible on Starknet where transaction ordering is observable. Gas cost is the only barrier. A sustained attack is economically rational for a party that benefits from suppressing staker rewards (e.g., a competing protocol or a staker seeking relative advantage).

### Recommendation
Add an access control check to `update_rewards` restricting callers to the authorized sequencer address (or a designated role). For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.roles.only_sequencer(); // or assert caller == sequencer_address
    ...
}
```

Alternatively, move the `last_reward_block.write` to after the `disable_rewards` guard so that a `disable_rewards: true` call does not consume the block slot.

### Proof of Concept
1. Consensus rewards are active (`!is_pre_consensus()`).
2. Attacker identifies any active staker `S` with non-zero balance.
3. At block N (before the sequencer acts), attacker calls:
   ```
   update_rewards(staker_address: S, disable_rewards: true)
   ```
4. `last_reward_block` is written to N; no rewards are distributed.
5. Sequencer calls `update_rewards(staker_address: S, disable_rewards: false)` at block N → reverts with `REWARDS_ALREADY_UPDATED`.
6. Block N rewards are permanently lost.
7. Attacker repeats at block N+1, N+2, … to freeze all future rewards.

**Root cause lines:** [1](#0-0) [2](#0-1) 

**Spec access-control requirement (violated):** [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
