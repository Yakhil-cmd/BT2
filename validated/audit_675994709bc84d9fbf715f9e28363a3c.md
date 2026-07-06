### Title
Unprivileged Caller Can Permanently Freeze Staker Block Rewards via `update_rewards` with `disable_rewards = true` — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in `staking.cairo` writes `last_reward_block` to storage **before** checking the `disable_rewards` flag, and the function has no access control. Any unprivileged caller can invoke `update_rewards(valid_staker, true)` to consume the current block number without distributing rewards, permanently preventing the legitimate block proposer from distributing consensus rewards for that block.

---

### Finding Description

In `StakingRewardsManagerImpl::update_rewards` the execution order is:

1. Assert `current_block_number > last_reward_block` (guard against double-processing).
2. Assert the staker is valid and active.
3. **Write `last_reward_block = current_block_number`** — the block is now permanently marked as processed.
4. Check `if disable_rewards || self.is_pre_consensus() { return; }` — if `disable_rewards` is `true`, the function exits without distributing any rewards. [1](#0-0) 

The only gate on the function is `general_prerequisites()`, which checks only that the contract is not paused and the caller is not the zero address. [2](#0-1) [3](#0-2) 

`last_reward_block` is a **single global** storage variable shared across all stakers. [4](#0-3) 

Because `last_reward_block` is updated before the early-return guard, an attacker who calls `update_rewards(any_active_staker, true)` in block N:

- Marks block N as processed in storage.
- Distributes **zero** rewards to any staker.
- Causes every subsequent call to `update_rewards` for block N to revert with `REWARDS_ALREADY_UPDATED`.

The analog to the external report is exact: one state variable (`last_reward_block`) is written to storage to record that the operation occurred, while the corresponding reward-accounting state (`staker_info.unclaimed_rewards_own`, `reward_supplier.update_unclaimed_rewards_from_staking_contract`) is **never updated** — leaving phantom "processed" blocks with no rewards distributed. [5](#0-4) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker repeating this call every block prevents **all** stakers from ever accumulating consensus block rewards. Because `last_reward_block` is global, a single call per block is sufficient to deny rewards to the entire protocol. The lost rewards are unrecoverable: there is no mechanism to retroactively credit a skipped block.

---

### Likelihood Explanation

**High.** The attack requires no special role, no capital, and no privileged key. The attacker only needs to:

1. Know any currently active staker address (publicly observable on-chain via `NewStaker` events or `stakers` vector).
2. Submit a transaction calling `update_rewards(staker_address, true)` before the legitimate block proposer does.

The cost is one transaction per block. On Starknet, transaction fees are low, making sustained griefing economically viable.

---

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` / `is_pre_consensus` check, so the block is only consumed when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);

let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
...
```

Alternatively, add an access-control check (e.g., `only_app_governor` or restrict to the attestation contract) so that only trusted callers can invoke `update_rewards`.

---

### Proof of Concept

```
Block N arrives.

1. Attacker (any EOA) calls:
       staking.update_rewards(active_staker_address, disable_rewards=true)

2. Inside update_rewards:
   - current_block_number (N) > last_reward_block  ✓  (guard passes)
   - staker is valid and active                     ✓  (guard passes)
   - last_reward_block.write(N)                     ← block N consumed
   - disable_rewards == true → return early         ← no rewards distributed

3. Legitimate block proposer calls:
       staking.update_rewards(staker_address, disable_rewards=false)
   → PANICS: "REWARDS_ALREADY_UPDATED"

4. All stakers permanently lose their consensus block rewards for block N.

5. Attacker repeats step 1 every block → protocol never distributes
   consensus rewards again.
``` [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1507)
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2362-2375)
```text
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
            // Emit event.
            self
                .emit(
                    Events::StakerRewardsUpdated {
                        staker_address, staker_rewards, pool_rewards: pool_rewards_list.span(),
                    },
                );

            // Write staker rewards to storage.
            self.write_staker_info(:staker_address, :staker_info);
```
