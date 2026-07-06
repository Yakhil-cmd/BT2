### Title
Unprivileged Caller Can Permanently Block Per-Block Reward Distribution via `update_rewards` - (File: src/staking/staking.cairo)

### Summary
Any non-zero address can call `update_rewards` with `disable_rewards: true` to advance the global `last_reward_block` sentinel without distributing any rewards. Because the sentinel is written **before** the early-return guard, every subsequent call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`, permanently denying the targeted staker(s) their consensus block rewards for that block.

### Finding Description
`StakingRewardsManagerImpl::update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero. [1](#0-0) 

Inside the function, `last_reward_block` is written to storage **before** the `disable_rewards` branch is evaluated: [2](#0-1) 

Because `last_reward_block` is a single global slot (not per-staker), one successful call in block N sets it to N for the entire contract. Any subsequent call in the same block hits:

```
assert!(current_block_number > self.last_reward_block.read(), …REWARDS_ALREADY_UPDATED);
```

and reverts. The consensus mechanism's legitimate call therefore cannot execute, and the block rewards for that block are permanently lost — there is no catch-up mechanism. [3](#0-2) 

The flow tests already document this revert behaviour explicitly: [4](#0-3) 

### Impact Explanation
In the consensus-rewards phase, `update_rewards` is the sole path through which per-block STRK rewards are credited to a staker's `unclaimed_rewards_own` and forwarded to delegation pools. Blocking it for a block means those rewards are never minted/credited and cannot be recovered in a later block. Repeated across many blocks this constitutes **permanent freezing (and effective theft) of unclaimed yield** — a High-severity impact under the allowed scope.

### Likelihood Explanation
The attack requires no privileged role, no capital, and no special setup beyond knowing a valid (active, non-zero-balance) staker address. The only cost is the gas for one transaction per block. Because `last_reward_block` is global, a single cheap call blocks reward distribution for every staker in that block. The attacker can sustain the attack indefinitely.

### Recommendation
1. **Move the `last_reward_block` write after the early-return guard** so that a `disable_rewards: true` call does not consume the block's reward slot.
2. **Add access control** to `update_rewards` (e.g., restrict to a designated consensus-rewards caller role), mirroring how `update_rewards_from_attestation_contract` is restricted to the attestation contract via `assert_caller_is_attestation_contract`. [5](#0-4) 

### Proof of Concept

```
Block N:
  1. Attacker (any EOA) calls:
       staking.update_rewards(staker_address = <any valid staker>, disable_rewards = true)
     → passes general_prerequisites() (not paused, caller ≠ 0)
     → passes REWARDS_ALREADY_UPDATED check (N > last_reward_block)
     → writes last_reward_block = N
     → hits `if disable_rewards { return; }` — no rewards distributed

  2. Consensus mechanism calls:
       staking.update_rewards(staker_address = <target staker>, disable_rewards = false)
     → assert!(N > N) FAILS → reverts with REWARDS_ALREADY_UPDATED

  3. Target staker's block-N rewards are permanently lost.

Repeat every block → continuous denial of yield for all stakers.
``` [6](#0-5)

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

**File:** src/flow_test/test.cairo (L2822-2829)
```text
    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: true);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
```
