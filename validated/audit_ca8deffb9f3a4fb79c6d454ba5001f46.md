### Title
Unprivileged Caller Can Permanently Grief All Stakers' Consensus Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function is publicly callable by anyone and accepts a caller-controlled `disable_rewards` parameter. Because `last_reward_block` is a **global** (not per-staker) storage variable, any caller can invoke `update_rewards(any_valid_staker, disable_rewards: true)` once per block to consume the block's reward slot without distributing any rewards, permanently blocking all stakers from earning consensus rewards for those blocks.

### Finding Description
`update_rewards` in `src/staking/staking.cairo` is the entry point for distributing per-block consensus rewards. It enforces a single-call-per-block invariant via the global `last_reward_block` storage variable:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: unpaused + non-zero caller
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // Update last block rewards.  <-- written BEFORE the disable_rewards check
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                    // exits without distributing any rewards
    }
    ...
}
```

The function:
1. Has **no access control** beyond `general_prerequisites()` (unpaused + non-zero caller). [1](#0-0) 
2. Accepts a **caller-controlled** `disable_rewards: bool` parameter.
3. Writes `last_reward_block` to the current block **before** checking `disable_rewards`. [2](#0-1) 
4. Returns early without distributing rewards when `disable_rewards` is `true`.

`last_reward_block` is a single global storage slot (not per-staker): [3](#0-2) 

Once any caller invokes `update_rewards(any_valid_staker, disable_rewards: true)` in a block, no other call to `update_rewards` can succeed in that same block (`REWARDS_ALREADY_UPDATED`). This allows an attacker to permanently prevent **all** stakers from earning consensus rewards by calling this function every block.

The analog to the Beanstalk report is direct: just as Beanstalk's `gm()` is a public state-transition function that can be called by anyone to advance seasons (bypassing the 2-season germination delay), Starknet Staking's `update_rewards` is a public state-transition function that can be called by anyone to advance `last_reward_block` — but with `disable_rewards: true`, the state advances without any rewards being distributed, and the global lock prevents legitimate callers from recovering in the same block.

### Impact Explanation
An unprivileged attacker calling `update_rewards(any_valid_staker, disable_rewards: true)` every block permanently denies all stakers their consensus rewards for those blocks. The rewards are never created, so stakers lose their rightful yield. This constitutes **griefing with no profit motive but damage to users or protocol** (Medium impact). If sustained, it amounts to a complete denial of consensus rewards for the entire protocol.

### Likelihood Explanation
- The attacker only needs to call `update_rewards` once per block — any valid staker address suffices.
- On Starknet, transaction costs are low, making sustained griefing economically feasible.
- No special privileges, leaked keys, or external dependencies are required.
- The attack is fully permissionless and reachable by any public caller.

### Recommendation
1. **Add access control**: Restrict `update_rewards` to be callable only by the staker themselves, their operational address, or a designated consensus contract.
2. **Validate `disable_rewards` on-chain**: Derive whether rewards should be disabled from verifiable on-chain data (e.g., whether the staker produced the block) rather than accepting it as a caller-supplied parameter.
3. **Make `last_reward_block` per-staker**: Change `last_reward_block` from a global variable to a `Map<ContractAddress, BlockNumber>` so one staker's call does not block others. [3](#0-2) 

### Proof of Concept
1. Attacker monitors Starknet for new blocks.
2. In each new block N, attacker calls `update_rewards(any_valid_staker_address, disable_rewards: true)`.
3. The function passes all checks (staker exists, has non-zero balance, block is new), writes `last_reward_block = N`, then returns early — no rewards distributed. [2](#0-1) 
4. Any legitimate call to `update_rewards` in block N now fails with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 
5. All stakers are denied rewards for block N.
6. Repeated every block, this permanently prevents all stakers from earning any consensus rewards.

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

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
