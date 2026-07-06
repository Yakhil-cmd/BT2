Based on my investigation of the actual implementation, this is a **real vulnerability**.

---

### Title
Missing Caller Access Control on `update_rewards` Allows Any Address to Suppress Block Rewards — (`src/staking/staking.cairo`)

### Summary

The `update_rewards` function is documented as "Only starkware sequencer" in the spec, but the implementation contains **no caller check**. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for that block and permanently discarding that block's rewards.

### Finding Description

`StakingRewardsManagerImpl::update_rewards` at [1](#0-0)  performs only:

1. `self.general_prerequisites()` — a pause check, **no role/caller check**
2. A block-level gate: `current_block_number > self.last_reward_block.read()` [2](#0-1) 

There is no `only_sequencer`, no `get_caller_address()` validation, and no role assertion anywhere in the function. The spec at [3](#0-2)  explicitly states access control is "Only starkware sequencer," but this is not enforced in code.

The critical state mutation is:

```cairo
self.last_reward_block.write(current_block_number);  // line 1485

if disable_rewards || self.is_pre_consensus() {
    return;  // line 1488 — exits with no rewards distributed
}
``` [4](#0-3) 

`last_reward_block` is a **global** (not per-staker) storage variable. Once written, any subsequent call in the same block — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`. [5](#0-4) 

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` before the sequencer's legitimate call in a given block:

- Writes `last_reward_block = current_block`
- Returns early, distributing **zero rewards**
- Causes the sequencer's subsequent call to revert with `REWARDS_ALREADY_UPDATED`
- That block's rewards are **permanently lost** — there is no catch-up or retry mechanism

This matches **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation

On Starknet, the sequencer controls transaction ordering and would normally place its own `update_rewards` call first. However:

- The missing access control is a concrete, code-level flaw that violates the stated invariant
- Any block where the sequencer's system call is delayed or absent is exploitable
- The attacker only needs one valid staker address (publicly enumerable via `get_stakers`)
- The `IStakingRewardsManager` interface is `#[abi(embed_v0)]`, making it fully externally callable [6](#0-5) 

### Recommendation

Add a sequencer-role check at the top of `update_rewards`, consistent with the spec's stated access control:

```cairo
fn update_rewards(...) {
    self.roles.only_sequencer(); // enforce "Only starkware sequencer"
    self.general_prerequisites();
    ...
}
```

### Proof of Concept

1. Deploy with two active stakers A and B, both past the K-epoch activation window, consensus rewards active.
2. From an arbitrary EOA, call `update_rewards(staker_A, disable_rewards: true)`.
3. Observe: `last_reward_block` is set to current block; staker A receives zero rewards.
4. Sequencer attempts `update_rewards(staker_B, disable_rewards: false)` — reverts with `REWARDS_ALREADY_UPDATED`.
5. Advance to next block; repeat step 2 for staker B.
6. After N blocks, both stakers have accumulated zero rewards despite being eligible. The `unclaimed_rewards_own` field never increases. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L1447-1448)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
```

**File:** src/staking/staking.cairo (L1449-1452)
```text
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

**File:** src/staking/staking.cairo (L1484-1507)
```text
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

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
