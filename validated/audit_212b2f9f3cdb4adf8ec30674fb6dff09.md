### Title
Unprivileged caller can grief all consensus reward distribution by calling `update_rewards` with `disable_rewards=true` every block — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable with no access control. It unconditionally writes `last_reward_block` to the current block number before checking the `disable_rewards` flag. Because only one `update_rewards` call is permitted per block (enforced by the `last_reward_block` guard), any unprivileged caller can invoke `update_rewards(valid_staker, true)` in every block to consume the per-block reward slot without distributing any rewards, permanently blocking all stakers from receiving consensus yield.

---

### Finding Description

**Root cause — `src/staking/staking.cairo` lines 1449–1507:**

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // ← last_reward_block is written HERE, before the disable_rewards check
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits with no rewards distributed
    }
    ...
}
```

`general_prerequisites()` only asserts the contract is unpaused and the caller is non-zero. There is no restriction on who may call `update_rewards` or what value they may pass for `disable_rewards`.

The global `last_reward_block` is written unconditionally before the early-return guard. Any subsequent call in the same block — including a legitimate call by the staker or the consensus mechanism — hits the `REWARDS_ALREADY_UPDATED` assertion and reverts.

**Attack path:**

1. Attacker reads any valid, active staker address from on-chain events (public information).
2. In every block, attacker calls `update_rewards(valid_staker_address, true)`.
3. `last_reward_block` is set to the current block; no rewards are distributed.
4. Every legitimate `update_rewards` call in that block fails with `REWARDS_ALREADY_UPDATED`.
5. Repeat indefinitely.

The staker validity checks (`is_staker_active`, `staker_total_strk_balance.is_non_zero`) are satisfied by any live staker, whose address is trivially discoverable from `NewStaker` events.

---

### Impact Explanation

All stakers are denied consensus rewards for every block in which the attacker acts. Unclaimed yield accrues to zero. The attack is sustained as long as the attacker continues calling the function — on Starknet, where per-transaction fees are low, this is economically feasible indefinitely.

**Impact category:** High — Temporary (and practically sustained) freezing of unclaimed yield for all protocol participants.

---

### Likelihood Explanation

- **No privileged access required.** Any non-zero address suffices.
- **No capital required.** The attacker does not need to stake or hold tokens.
- **Staker address is public.** `NewStaker` events expose valid staker addresses.
- **Low cost on Starknet.** Calling one function per block is cheap; the attacker has no profit motive but can cause severe damage.

Likelihood: **High**.

---

### Recommendation

Move the `last_reward_block` write to after the `disable_rewards` guard, so that a no-op call does not consume the block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
// ... reward distribution logic ...
```

Alternatively, restrict who may pass `disable_rewards=true` (e.g., only the staker themselves or a privileged role), or remove the `disable_rewards` parameter from the public interface entirely if it is not needed by external callers.

---

### Proof of Concept

```
// Setup: staker_address is any active staker (read from NewStaker event)
// Attacker address: any non-zero address

// In every block N:
staking_contract.update_rewards(staker_address, disable_rewards=true)
// → last_reward_block = N, no rewards distributed

// Any legitimate call in block N:
staking_contract.update_rewards(staker_address, disable_rewards=false)
// → PANICS: REWARDS_ALREADY_UPDATED

// Result: zero consensus rewards distributed to any staker for every block
//         the attacker sustains the call.
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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
