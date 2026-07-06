### Title
Front-Running `update_rewards()` Steals Block Proposer's Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function uses a single global `last_reward_block` slot to enforce one reward update per block. Because the function is public, accepts any `staker_address`, and hard-reverts when the slot is already consumed, an attacker who is a registered staker can front-run the legitimate block proposer's call, steal the block rewards, and cause the proposer's transaction to revert.

---

### Finding Description

`update_rewards` (lines 1449–1507) is callable by any non-zero address. Its `general_prerequisites()` guard only checks that the contract is unpaused and the caller is non-zero — no role restriction exists. [1](#0-0) 

The function first asserts that the current block has not yet been processed:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

It then writes the current block number to the global `last_reward_block` slot and distributes block rewards to the caller-supplied `staker_address`: [3](#0-2) 

`last_reward_block` is a single shared storage value — only one call per block can succeed. Because `staker_address` is a free parameter and there is no check that the caller is the block proposer, an attacker who is a registered staker can:

1. Observe the legitimate block proposer's pending `update_rewards(proposer, false)` in the mempool.
2. Submit `update_rewards(attacker_staker, false)` with higher gas to land first.
3. The attacker's call succeeds: `last_reward_block` is updated and block rewards flow to the attacker's staker via `_update_rewards`.
4. The proposer's call reverts with `REWARDS_ALREADY_UPDATED`.

In V3 consensus-rewards mode the per-block STRK reward distributed to the winning staker is:

```
staker_own_rewards = strk_block_rewards × own_balance / staker_total_strk_balance
``` [4](#0-3) 

The attacker receives a positive reward proportional to their own stake; the legitimate proposer receives zero for that block.

The `general_prerequisites` guard that is the only barrier: [5](#0-4) 

---

### Impact Explanation

**High — Theft of unclaimed yield.** The legitimate block proposer permanently loses their block rewards for every attacked block. The attacker's staker receives rewards it is not entitled to. The attack is repeatable every block, enabling systematic drain of block-proposer rewards.

---

### Likelihood Explanation

**Medium.** The attacker must be a registered staker (minimum stake required, but this is a low barrier via `stake()`). Block proposers are deterministic and known in advance from the consensus schedule, making targeted front-running straightforward. The attack requires only mempool monitoring and gas priority manipulation — standard capabilities on Starknet.

---

### Recommendation

Derive the rewarded staker from the caller's identity rather than accepting it as a free parameter, mirroring how `attest()` uses `get_caller_address()` as the operational address and then resolves the staker: [6](#0-5) 

Alternatively, add an explicit check that `staker_address` corresponds to the current block's designated proposer before writing `last_reward_block` and distributing rewards.

---

### Proof of Concept

1. Block N's designated proposer is staker A (operational address `op_A`).
2. Staker A submits `update_rewards(A, false)` to claim block N rewards.
3. Attacker (staker B) sees A's pending transaction in the mempool.
4. Attacker submits `update_rewards(B, false)` with higher gas.
5. B's transaction is included first: `last_reward_block` is set to N; B's staker receives `strk_block_rewards × B_own / B_total`.
6. A's transaction is included next and reverts at the `REWARDS_ALREADY_UPDATED` assert (line 1457).
7. A receives zero rewards for block N.
8. Attacker repeats every block to systematically steal block-proposer rewards. [7](#0-6)

### Citations

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L1905-1924)
```text
        fn calculate_staker_own_rewards(
            self: @ContractState,
            staker_address: ContractAddress,
            strk_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            curr_epoch: Epoch,
        ) -> Amount {
            let own_balance_curr_epoch = self
                .get_staker_own_balance_at_epoch(:staker_address, epoch_id: curr_epoch);
            // In V3 (consensus rewards), this error is unreachable since `update_rewards` is not
            // valid for stakers without balance.
            assert!(own_balance_curr_epoch.is_non_zero(), "{}", Error::ATTEST_WITH_ZERO_BALANCE);

            mul_wide_and_div(
                lhs: strk_total_rewards,
                rhs: own_balance_curr_epoch.to_strk_native_amount(),
                div: strk_total_stake.to_strk_native_amount(),
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
        }
```

**File:** src/attestation/attestation.cairo (L116-134)
```text
        fn attest(ref self: ContractState, block_hash: felt252) {
            let operational_address = get_caller_address();
            let staking_dispatcher = IStakingAttestationDispatcher {
                contract_address: self.staking_contract.read(),
            };
            // Note: This function checks for a zero staker address and will panic if so.
            let staking_attestation_info = staking_dispatcher
                .get_attestation_info_by_operational_address(:operational_address);
            self._validate_attestation(:block_hash, :staking_attestation_info);
            // Work is one tx per epoch.
            self
                ._mark_attestation_is_done(
                    staker_address: staking_attestation_info.staker_address(),
                    current_epoch: staking_attestation_info.epoch_id(),
                );
            staking_dispatcher
                .update_rewards_from_attestation_contract(
                    staker_address: staking_attestation_info.staker_address(),
                );
```
