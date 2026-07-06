### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze All Staking Rewards — (`src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is specified to be callable only by the Starknet sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true` to consume the single global `last_reward_block` slot for the current block without distributing any rewards. Repeated every block, this permanently freezes all unclaimed yield for every staker and delegator in the protocol.

---

### Finding Description

The protocol specification explicitly states the access control for `update_rewards`:

> **"Only starkware sequencer."** — `docs/spec.md` line 1645

However, the implementation only calls `general_prerequisites()`, which checks `is_paused` and `caller_is_not_zero` — no sequencer identity check exists:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only checks: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ...
    self.last_reward_block.write(current_block_number);   // ← written BEFORE disable check

    if disable_rewards || self.is_pre_consensus() {
        return;   // ← no rewards distributed, but slot is consumed
    }
    // ...
}
``` [1](#0-0) 

The critical design flaw is that `last_reward_block` is a **single global value** (not per-staker):

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

Because `last_reward_block` is written unconditionally before the `disable_rewards` branch, a single call to `update_rewards(any_valid_staker, disable_rewards: true)` in block N:

1. Passes all prerequisite checks (contract not paused, caller not zero, staker active, staker has non-zero balance).
2. Writes `last_reward_block = N`.
3. Returns immediately — **zero rewards distributed**.
4. Any subsequent call in block N (including the legitimate sequencer call for any staker) reverts with `REWARDS_ALREADY_UPDATED`.

The spec's stated access control is never enforced: [3](#0-2) 

---

### Impact Explanation

An attacker calling `update_rewards(valid_staker, true)` once per block permanently freezes all unclaimed STRK yield for every staker and every delegation pool member in the protocol. No staker receives block rewards; no pool receives its share. This matches the **High: Permanent freezing of unclaimed yield** impact category.

---

### Likelihood Explanation

- **Entry path**: Any unprivileged EOA or contract — no special role, no leaked key, no bridge interaction required.
- **Required knowledge**: Any valid, active staker address (trivially obtained from `NewStaker` events).
- **Cost**: One cheap Starknet transaction per block. Starknet L2 fees are low, making sustained griefing economically viable.
- **No profit motive needed**: The attacker loses only gas; the protocol loses all consensus-era reward distribution.

---

### Recommendation

Add an explicit caller check to `update_rewards` so only the authorized sequencer address (or a designated role) can invoke it, consistent with the spec:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // enforce spec: "Only starkware sequencer"
    // ...
}
```

Alternatively, store `last_reward_block` per-staker so that one call cannot block all others, though the access-control fix is the primary mitigation.

---

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and passed).
2. Attacker identifies any valid, active staker address `S` from on-chain `NewStaker` events.
3. At the start of every block N, attacker submits:
   ```
   staking.update_rewards(S, disable_rewards=true)
   ```
4. Inside the call:
   - `general_prerequisites()` passes (contract not paused, attacker address ≠ 0).
   - `current_block_number (N) > last_reward_block` passes (first call this block).
   - Staker `S` is active with non-zero balance — passes.
   - `last_reward_block` is written to `N`.
   - `disable_rewards == true` → function returns; **no rewards minted or transferred**.
5. The sequencer's legitimate call to `update_rewards(any_staker, false)` in block N reverts: `REWARDS_ALREADY_UPDATED`.
6. Repeated every block: all stakers and all delegation pool members receive zero block rewards indefinitely. [4](#0-3) [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1489)
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

            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

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

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
