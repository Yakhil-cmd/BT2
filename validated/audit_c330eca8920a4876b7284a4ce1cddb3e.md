### Title
Unprivileged caller can permanently freeze all staker rewards by calling `update_rewards` with `disable_rewards: true` every block — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the staking contract is publicly callable by any non-zero address and accepts a caller-controlled `disable_rewards: bool` parameter. When called with `disable_rewards: true`, the function unconditionally advances the global `last_reward_block` to the current block but skips all reward distribution. Because the function enforces `current_block_number > last_reward_block`, an attacker who calls `update_rewards(valid_staker, true)` once per block permanently consumes every block's reward slot, causing all stakers to receive zero rewards indefinitely.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is not paused and that the caller is not the zero address. [1](#0-0) 

No role check, no allowlist, and no restriction to the attestation contract or any privileged address is present. The function then unconditionally writes the current block number to the global `last_reward_block` storage slot before inspecting `disable_rewards`: [2](#0-1) 

Because `last_reward_block` is a single global value shared across all stakers, once it is set to `current_block_number`, the guard at the top of the function: [3](#0-2) 

prevents any subsequent call in the same block from distributing rewards. An attacker who submits `update_rewards(any_active_staker, true)` as the first transaction of every block therefore silently discards every epoch's block rewards for every staker in the protocol.

The `disable_rewards` branch that causes the early return without reward distribution: [4](#0-3) 

---

### Impact Explanation

Every block's STRK (and BTC) rewards are computed and distributed inside `_update_rewards`, which is only reached when `disable_rewards` is false and the protocol is post-consensus. By consuming `last_reward_block` with `disable_rewards: true`, the attacker causes the staking contract to never call `_update_rewards`, so `unclaimed_rewards_own` for every staker and every pool member is never incremented. This constitutes **permanent freezing of unclaimed yield** for all participants in the protocol.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield or unclaimed royalties**.

---

### Likelihood Explanation

- The function is fully public; no special role or token ownership is required.
- The attacker only needs to know any currently active staker address (trivially readable from on-chain events or the `stakers` vector).
- On Starknet, transaction fees are low enough that calling one transaction per block is economically viable for a motivated attacker.
- The attack is silent: no revert, no anomalous event, just zero rewards accumulating.

---

### Recommendation

Restrict `update_rewards` to callers that are legitimately part of the reward-distribution pipeline (e.g., the attestation contract, or a designated keeper role). If the function must remain permissionless, the `disable_rewards` parameter should be removed from the public interface and replaced with an internal determination of whether rewards should be skipped (e.g., based on whether the staker attested). At minimum, `disable_rewards: true` should only be settable by a trusted caller such as the attestation contract.

---

### Proof of Concept

```
// Attacker script (pseudocode, one call per block)
loop every block:
    staking_contract.update_rewards(
        staker_address = <any_valid_active_staker>,
        disable_rewards = true
    )
// Effect:
// - last_reward_block is set to current_block_number
// - _update_rewards is never reached
// - All stakers accumulate zero unclaimed_rewards_own forever
// - Pool members accumulate zero rewards forever
```

The root cause is the absence of any access control on `update_rewards` combined with the unconditional write to `last_reward_block` before the `disable_rewards` branch is evaluated. [5](#0-4)

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
