### Title
Unprivileged Caller Can Permanently Suppress All Stakers' Block Rewards via Unvalidated `disable_rewards` Parameter in `update_rewards` — (File: `src/staking/staking.cairo`)

---

### Summary

The public `update_rewards` function accepts a caller-controlled `disable_rewards: bool` parameter that determines whether rewards are distributed. Any unprivileged address can invoke it with `disable_rewards: true` to advance the **global** `last_reward_block` checkpoint without distributing rewards, permanently preventing all stakers from receiving rewards for that block.

---

### Finding Description

`update_rewards` in `src/staking/staking.cairo` is exposed via `IStakingRewardsManager` with no role-based access control beyond `general_prerequisites`, which only checks the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function accepts a `disable_rewards: bool` parameter that routes execution into two distinct code paths: [2](#0-1) 

The critical flaw is the ordering of operations:

1. The function asserts `current_block_number > last_reward_block` (line 1454–1458).
2. It **unconditionally** writes `last_reward_block = current_block_number` (line 1485).
3. Only *after* that write does it check `disable_rewards` and potentially return early without distributing rewards (line 1487–1489).

`last_reward_block` is a **global** (not per-staker) storage variable: [3](#0-2) 

Once it is set to block N, the assertion on line 1454 will fail for any subsequent call targeting block N, making the reward loss for that block **permanent and irrecoverable** for every staker in the system.

The `disable_rewards` parameter is never validated against the caller's identity or role: [4](#0-3) 

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_staker_address, disable_rewards: true)` once per block. Because `last_reward_block` is global, this single call:

- Consumes the block's reward slot for **all** stakers simultaneously.
- Prevents `_update_rewards` from being called, so no staker's `unclaimed_rewards_own` is incremented for that block.
- Cannot be undone — the `REWARDS_ALREADY_UPDATED` assertion permanently blocks any retry for block N.

Rewards that were never added to `unclaimed_rewards_own` can never be claimed via `claim_rewards`. This constitutes **permanent freezing of unclaimed yield** for all stakers, matching the **High** impact tier.

---

### Likelihood Explanation

**High.** The function is callable by any non-zero address with no additional restrictions. The attacker needs only a valid staker address (publicly enumerable from `NewStaker` events) and a single transaction per block. Gas cost is the only barrier, and it is trivially low relative to the yield stolen from the entire staker set.

---

### Recommendation

1. **Remove `disable_rewards` from the public interface.** If the parameter is needed internally (e.g., during staker removal), expose a separate privileged entry point restricted to a governance or operator role.
2. **Alternatively**, add a caller check: assert that `get_caller_address()` is the attestation contract or a whitelisted operator before allowing `disable_rewards: true`.
3. **At minimum**, move the `last_reward_block.write(current_block_number)` call to *after* the `disable_rewards` branch so that a no-op call does not consume the block's reward slot.

---

### Proof of Concept

```
// Attacker script (pseudocode, runs once per block)
for each new block N:
    staking_contract.update_rewards(
        staker_address = any_active_staker,   // publicly known
        disable_rewards = true                // attacker-controlled
    )
    // Effect:
    //   last_reward_block := N
    //   _update_rewards NOT called
    //   All stakers lose rewards for block N permanently
    //   Any legitimate call to update_rewards for block N now reverts
    //   with REWARDS_ALREADY_UPDATED
```

The analog to M-03 is direct: just as Swivel's `lend()` failed to validate `o.exit`/`o.vault` before an external call, allowing an attacker to route execution into an unintended code path that altered token accounting, `update_rewards` here fails to validate `disable_rewards` against the caller's identity, allowing any attacker to route execution into the "no rewards" path while still consuming the global block-reward checkpoint — permanently suppressing yield for all stakers.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1460)
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
