### Title
Unrestricted `update_rewards` with `disable_rewards=true` Enables Permanent Freezing of All Staker Yield — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the `Staking` contract is callable by any unprivileged address. When invoked with `disable_rewards: true`, it advances the global `last_reward_block` checkpoint without distributing any rewards. Because `last_reward_block` is a single protocol-wide variable, one such call per block is sufficient to permanently block every staker from receiving consensus-era yield.

---

### Finding Description

`update_rewards` is exposed through `IStakingRewardsManager` with no role-based access control. Its only gate is `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero. [1](#0-0) 

When `disable_rewards: true` is passed, the function writes the current block number to the global `last_reward_block` and returns immediately, distributing nothing. [2](#0-1) 

Any subsequent call to `update_rewards` in the same block — including a legitimate one from the attestation contract or a staker — fails with `REWARDS_ALREADY_UPDATED` because of the strict `>` check: [3](#0-2) 

`last_reward_block` is a single global storage slot, not per-staker: [4](#0-3) 

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` on every block therefore occupies the sole reward slot for every block, starving the entire staker set of consensus-era yield indefinitely.

The only prerequisite is a valid, active staker address with non-zero balance — information that is fully public on-chain. The attacker needs no stake, no special role, and no capital.

---

### Impact Explanation

- **All** stakers' unclaimed consensus-era yield is frozen for as long as the attacker sustains the call stream.
- The attacker has zero profit motive; the damage is purely to stakers and protocol health.
- Matches **High: Permanent freezing of unclaimed yield / Temporary freezing of funds**.

---

### Likelihood Explanation

- Any non-zero address can execute the attack; no privileged access is required.
- Starknet transaction fees are low, making per-block calls economically viable.
- The attack is trivially automatable with a single-line script that monitors new blocks and fires the call.
- The required `staker_address` argument is freely discoverable from on-chain events (`NewStaker`).

---

### Recommendation

1. **Restrict `disable_rewards`**: Gate the `disable_rewards: true` path behind a privileged role (e.g., `only_security_agent`) or remove the parameter entirely, handling the pre-consensus no-op case inside the function without touching `last_reward_block`.
2. **Per-staker reward block tracking**: Replace the single global `last_reward_block` with a per-staker mapping so one call cannot block all others.
3. **Caller whitelist**: Restrict `update_rewards` to the attestation contract or a designated operator role, consistent with how `update_rewards_from_attestation_contract` is already protected. [5](#0-4) 

---

### Proof of Concept

1. Attacker observes any active staker address `S` with non-zero STRK balance (e.g., from a `NewStaker` event).
2. Attacker deploys a bot that, on every new Starknet block, calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. Each call passes `general_prerequisites()` (non-zero caller, contract unpaused), passes the staker-active check, writes `last_reward_block = current_block`, and returns without distributing rewards.
4. Any legitimate `update_rewards` call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Result: zero consensus-era rewards are distributed to any staker for the duration of the attack. All `unclaimed_rewards_own` balances remain frozen at their pre-attack values. [6](#0-5)

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

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```
