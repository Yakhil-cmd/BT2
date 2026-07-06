### Title
Unguarded `disable_rewards` Parameter in `update_rewards` Allows Any Caller to Permanently Block Consensus Reward Distribution — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards: bool` parameter with no authorization check. Any unprivileged caller can invoke `update_rewards(valid_staker, true)` each block to advance the global `last_reward_block` sentinel without distributing rewards, permanently starving all stakers of consensus-era block rewards.

---

### Finding Description

**Vulnerability class:** Authorization bypass via unvalidated caller-controlled parameter (direct analog to the unvalidated `request.method` lookup in the reference report — both allow an attacker to invoke unintended behavior through an unguarded caller-supplied input).

`update_rewards` is gated only by `general_prerequisites()`, which checks two things: the contract is not paused, and the caller is not the zero address. [1](#0-0) 

No check is made that the caller is the staker, the attestation contract, or any other authorized party.

The function then unconditionally writes `current_block_number` to `last_reward_block` **before** branching on `disable_rewards`: [2](#0-1) 

Because `last_reward_block` is already advanced, the guard at the top of the function will reject any subsequent call in the same block: [3](#0-2) 

When `disable_rewards` is `true`, the function returns immediately after writing `last_reward_block`, skipping the entire reward calculation and distribution path: [4](#0-3) 

The `staker_address` parameter is also fully caller-controlled (it is not `get_caller_address()`), so the attacker only needs to supply any currently active staker with non-zero balance to pass the validity checks. [5](#0-4) 

---

### Impact Explanation

In the consensus rewards era (after `consensus_rewards_first_epoch` is set), `update_rewards` is the sole mechanism by which block rewards are distributed to stakers and their delegation pools. By calling `update_rewards(valid_staker, true)` on every block, an attacker causes `last_reward_block` to advance each block while no rewards are ever computed or transferred. All stakers are permanently denied their unclaimed yield. This matches the allowed impact: **Permanent freezing of unclaimed yield** (High).

---

### Likelihood Explanation

The attack requires no privileged role, no leaked key, and no external dependency. Any EOA with enough gas to submit one transaction per block can execute it indefinitely. The cost is purely gas; there is no economic barrier. The attacker needs only to know one valid, active staker address, which is publicly observable on-chain via the `stakers` vector and emitted events.

---

### Recommendation

Add an authorization check inside `update_rewards` so that only the staker themselves (i.e., `get_caller_address() == staker_address`) or a designated trusted caller (e.g., the attestation contract) may invoke it. Alternatively, remove `disable_rewards` from the public ABI entirely and handle the "disable" case through a separate privileged admin function.

---

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and the current epoch has passed it).
2. Attacker identifies any valid, active staker `S` with non-zero STRK balance (readable from public storage/events).
3. Each block, attacker submits: `staking_contract.update_rewards(S, disable_rewards: true)`.
4. Inside the call: staker validity checks pass → `last_reward_block` is written to the current block → `disable_rewards == true` → function returns with no rewards distributed.
5. Any legitimate call to `update_rewards` in the same block hits `REWARDS_ALREADY_UPDATED` and reverts.
6. Repeated every block, no staker ever accumulates consensus block rewards. All unclaimed yield is permanently frozen. [6](#0-5)

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
