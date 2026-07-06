### Title
Unprivileged Caller Can Permanently Freeze Consensus Rewards for All Stakers via `update_rewards(disable_rewards: true)` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the `Staking` contract is publicly callable with no meaningful access control. It accepts a `disable_rewards` boolean parameter and unconditionally writes to the global `last_reward_block` storage variable **before** checking that flag. Any unprivileged caller can invoke `update_rewards(staker_address, disable_rewards: true)` once per block to consume the per-block reward slot without distributing any rewards, permanently starving all stakers of consensus-era block rewards.

---

### Finding Description

`update_rewards` is exposed as a public entry point under `IStakingRewardsManager`. Its only gate is `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role check, no staker-ownership check. [1](#0-0) 

Inside the function, `last_reward_block` is written to storage **before** the `disable_rewards` branch: [2](#0-1) 

`last_reward_block` is a **single global** field, not per-staker: [3](#0-2) 

The guard that prevents double-calls in the same block is: [4](#0-3) 

Because `last_reward_block` is global, once any caller writes the current block number there, **every** subsequent call in that block reverts with `REWARDS_ALREADY_UPDATED`. The attacker therefore consumes the single per-block reward slot for the entire protocol without distributing a single token.

The `general_prerequisites` function confirms there is no role restriction: [5](#0-4) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

By calling `update_rewards(any_active_staker, disable_rewards: true)` in every block, an attacker prevents the entire consensus reward distribution mechanism from ever executing. All stakers permanently lose block rewards they are entitled to. The yield is not redirected — it is simply never credited, constituting permanent freezing of unclaimed yield for every participant in the protocol.

---

### Likelihood Explanation

**High.** The attack requires:
- No special role or privilege.
- No capital at risk.
- One cheap Starknet transaction per block.

The attacker only needs to ensure their transaction lands before any legitimate `update_rewards` call in each block. On Starknet, transaction costs are low enough to make this economically viable for any motivated adversary (e.g., a competing validator set, a protocol saboteur, or a griefing actor).

---

### Recommendation

1. **Restrict `disable_rewards: true` to a privileged role** (e.g., `only_operator` or `only_app_governor`), or remove the parameter from the public interface entirely.
2. Alternatively, **move the `last_reward_block` write to after the `disable_rewards` check**, so that a call with `disable_rewards: true` does not consume the per-block slot.
3. Consider making `last_reward_block` per-staker if the intent is to allow independent per-staker reward updates.

---

### Proof of Concept

```
// Attacker script — repeat every block:
staking_contract.update_rewards(
    staker_address = <any valid active staker>,
    disable_rewards = true
)
```

Step-by-step:

1. Block N begins. `last_reward_block < N`.
2. Attacker calls `update_rewards(valid_staker, disable_rewards=true)`.
3. `general_prerequisites()` passes (contract unpaused, caller non-zero).
4. Assert `N > last_reward_block` passes.
5. `last_reward_block.write(N)` executes — slot consumed.
6. `disable_rewards == true` → function returns with no rewards distributed.
7. Any legitimate staker or sequencer that now calls `update_rewards` in block N hits `REWARDS_ALREADY_UPDATED` and reverts.
8. Repeat in block N+1, N+2, … → **zero consensus rewards ever distributed**. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1507)
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
```

**File:** src/staking/staking.cairo (L1794-1797)
```text
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
