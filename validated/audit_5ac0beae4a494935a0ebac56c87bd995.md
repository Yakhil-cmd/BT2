### Title
Unprivileged Caller Can Permanently Freeze Consensus Block Rewards via `update_rewards` with `disable_rewards: true` - (File: `src/staking/staking.cairo`)

### Summary

`IStakingRewardsManager::update_rewards` is a public function with no caller access control. It accepts a `disable_rewards: bool` parameter. Because `last_reward_block` is a global, per-block gate, any unprivileged caller can invoke `update_rewards(any_active_staker, disable_rewards: true)` to consume the one-allowed-call-per-block slot without distributing rewards, permanently denying all stakers their consensus block rewards for that block.

### Finding Description

`update_rewards` in `StakingRewardsManagerImpl` enforces a single-call-per-block invariant via `last_reward_block`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // consumes the slot for this block

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits without distributing rewards
    }
    ...
``` [1](#0-0) 

`general_prerequisites` only asserts the contract is unpaused and the caller is non-zero — no role or identity check: [2](#0-1) 

The `disable_rewards` flag is intended to skip reward distribution in certain protocol states, but because there is no restriction on who may pass `true`, any external account can exploit it.

Compare with `update_rewards_from_attestation_contract`, which correctly gates its caller:

```cairo
fn update_rewards_from_attestation_contract(...) {
    ...
    self.assert_caller_is_attestation_contract();   // explicit caller check
    ...
``` [3](#0-2) 

`update_rewards` has no equivalent guard.

### Impact Explanation

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` once per block. This:

1. Writes `current_block_number` into `last_reward_block`, consuming the per-block slot.
2. Returns immediately without distributing any block rewards.
3. Every subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.

All stakers lose their consensus block rewards for every block the attacker front-runs. Because the missed block rewards are never re-queued, the loss is permanent — matching **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- No tokens, stake, or privileged role required — only gas.
- The attacker needs only a valid active staker address, which is publicly observable on-chain.
- The attack is repeatable every block at negligible cost.
- Likelihood: **High**.

### Recommendation

Add an explicit caller check to `update_rewards`, restricting who may invoke it with `disable_rewards: true`. For example, only allow a designated keeper role or the attestation contract to call the function, mirroring the pattern used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
+   self.roles.only_rewards_manager();   // or assert_caller_is_attestation_contract()
    self.general_prerequisites();
    ...
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the pre-consensus / disable logic internally.

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker (any EOA) observes an active staker address `S` on-chain.
3. At the start of block `N`, attacker calls:
   ```
   staking.update_rewards(S, disable_rewards: true)
   ```
4. `last_reward_block` is set to `N`; no rewards are distributed.
5. The legitimate keeper (or any honest party) calls `update_rewards(S, false)` in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
6. Staker `S` (and all other stakers, since `last_reward_block` is global) receives zero block rewards for block `N`.
7. Attacker repeats step 3 every block, permanently freezing all consensus block rewards. [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

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
