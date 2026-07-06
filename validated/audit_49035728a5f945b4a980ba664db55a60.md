### Title
Unprivileged Caller Can Permanently Freeze Consensus Rewards via `disable_rewards` Parameter in `update_rewards` — (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is a public, permissionless function that accepts a caller-controlled `disable_rewards: bool` parameter. When set to `true`, the function advances `last_reward_block` to the current block while silently skipping all reward computation. Because the function enforces a strict "one call per block" invariant, any unprivileged actor can call `update_rewards(any_staker, true)` every block to permanently prevent stakers from ever accumulating consensus rewards.

---

### Finding Description

`update_rewards` is exposed as a public ABI entry point under `StakingRewardsManagerImpl`:

```
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only checks: not paused, caller != zero
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // ← slot consumed

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← rewards skipped
    }
    ...
``` [1](#0-0) 

`general_prerequisites` enforces only two conditions — the contract is not paused and the caller is not the zero address: [2](#0-1) 

There is no role check, no whitelist, and no restriction on who may supply `disable_rewards: true`. The one-call-per-block guard (`current_block_number > last_reward_block`) is the only gate, and it is consumed by the attacker's call regardless of whether rewards were actually distributed.

The analog to the original report's vulnerability class is direct:

| Original report | This codebase |
|---|---|
| `amountMinOut` calculated from manipulatable pool state | `disable_rewards` supplied by an arbitrary caller |
| Slippage parameter based on manipulatable values | `last_reward_block` advanced without distributing rewards |
| No proposal rejection mechanism | No access control on `update_rewards` |

---

### Impact Explanation

An attacker who calls `update_rewards(victim_staker, true)` once per block:

1. Advances `last_reward_block` to the current block number.
2. Causes the function to return early, skipping `_update_rewards` entirely.
3. Blocks every legitimate caller (the consensus layer, the staker, or any helper) from calling `update_rewards` again in the same block, because the `REWARDS_ALREADY_UPDATED` assertion will revert.

Repeated across every block, this permanently freezes the accumulation of consensus rewards (`unclaimed_rewards_own`) for any targeted staker and their delegation pool. Stakers can never claim rewards that were never computed.

This matches the allowed impact: **Permanent freezing of unclaimed yield**. [3](#0-2) 

---

### Likelihood Explanation

- The function is publicly callable with no privilege requirement.
- The attacker needs only gas; no capital, no stake, no special role.
- The attack is fully automatable: a bot submits one transaction per block targeting any staker.
- The cost to the attacker is low (one cheap call per block); the damage to the victim is total loss of consensus rewards for the duration of the attack.

---

### Recommendation

Restrict `update_rewards` to callers that are authorized to submit consensus reward updates (e.g., the attestation contract, a designated consensus reporter role, or the staker/operational address themselves). Remove the `disable_rewards` parameter from the public interface entirely, or gate it behind an appropriate role check such as `only_security_agent` or `only_app_governor`.

---

### Proof of Concept

1. Staker `S` is active and eligible for consensus rewards.
2. Attacker `A` (any EOA) monitors the mempool for the start of each new block.
3. Each block, `A` calls:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The call passes `general_prerequisites` (not paused, caller != zero).
5. `last_reward_block` is set to the current block number.
6. The function returns early — no rewards are computed or credited.
7. Any subsequent call to `update_rewards` for staker `S` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
8. After N blocks of this attack, staker `S` has accumulated zero consensus rewards despite being fully active and attesting correctly.
9. `S`'s `unclaimed_rewards_own` remains at its pre-attack value indefinitely. [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1448-1508)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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
