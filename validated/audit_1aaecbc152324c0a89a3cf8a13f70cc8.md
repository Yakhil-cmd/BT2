### Title
Unprivileged caller can permanently freeze consensus-phase block rewards for all stakers via `update_rewards(disable_rewards: true)` — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` is a public, permissionless function that accepts a caller-controlled `disable_rewards: bool` parameter. When called with `disable_rewards: true`, it advances the global `last_reward_block` to the current block **without distributing any rewards**, and the per-block guard then prevents any subsequent call for that same block. An unprivileged attacker calling this once per block can permanently freeze all consensus-phase block rewards for every staker in the protocol.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is exposed with no role check beyond `general_prerequisites()`, which only asserts the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function immediately writes the current block number to the global `last_reward_block` storage slot: [2](#0-1) 

After that write, the function checks `disable_rewards` and returns early — skipping all reward computation and distribution — if the caller passed `true`: [3](#0-2) 

Because `last_reward_block` is a **single global slot** (not per-staker), the guard at the top of the function: [4](#0-3) 

ensures that once any caller has invoked `update_rewards` for block N (even with `disable_rewards: true`), **no further call for block N can succeed**. The slot is consumed, the rewards for that block are gone.

The only prerequisite is that the attacker supplies a currently-active staker address with non-zero balance, both of which are trivially discoverable on-chain from `NewStaker` events. [5](#0-4) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

In the consensus phase (`is_pre_consensus() == false`), block rewards are the sole mechanism by which stakers and delegators accumulate yield. By calling `update_rewards(any_active_staker, disable_rewards: true)` once per block, an attacker:

1. Marks the block as "already processed" in `last_reward_block`.
2. Causes the function to return before any STRK or BTC block rewards are computed or transferred.
3. Prevents any legitimate caller from distributing rewards for that block.

Repeated across every block, this permanently freezes all unclaimed yield for all stakers and all delegation pool members. No funds already staked are moved, but all future reward accrual is halted.

---

### Likelihood Explanation

**High.** The attack requires:
- A non-zero caller address (any EOA or contract).
- One valid active staker address (publicly observable from on-chain events).
- One transaction per block.

There is no economic barrier, no privileged access, and no dependency on external systems. The cost is purely gas per block.

---

### Recommendation

1. **Restrict `disable_rewards` to the staker themselves or a designated operator.** Add an access check so that only `staker_address` (or their `operational_address`) may pass `disable_rewards: true`.
2. **Alternatively, remove the `disable_rewards` parameter entirely** if it is not required by the external consensus layer, and handle the pre-consensus short-circuit solely via `is_pre_consensus()`.
3. **Consider making `last_reward_block` per-staker** if independent per-staker reward updates are the intended design, so that one call cannot block all others.

---

### Proof of Concept

```
// Attacker script (pseudocode, runs once per block)
let active_staker = fetch_any_active_staker_from_events();
staking_contract.update_rewards(
    staker_address: active_staker,
    disable_rewards: true   // <-- attacker-controlled
);
// last_reward_block is now set to current block.
// No rewards distributed. No one else can call update_rewards this block.
// Repeat next block.
```

Concrete entry path:
1. Attacker observes a `NewStaker` event to obtain a valid `staker_address`.
2. At the start of each block, attacker calls `Staking::update_rewards(staker_address, true)`.
3. `general_prerequisites()` passes (contract unpaused, caller non-zero). [6](#0-5) 
4. `last_reward_block` is written to the current block number. [7](#0-6) 
5. `disable_rewards == true` → early return, zero rewards distributed. [3](#0-2) 
6. Any subsequent legitimate call to `update_rewards` for the same block reverts with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 
7. All stakers and delegators receive zero block rewards for that block.

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

**File:** src/staking/staking.cairo (L1466-1483)
```text
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
