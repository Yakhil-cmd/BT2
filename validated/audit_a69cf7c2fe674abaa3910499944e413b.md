### Title
Unprivileged Caller Can Permanently Freeze Consensus Block Rewards for All Stakers via `update_rewards` - (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager.update_rewards` has no caller access control. Any address can invoke it with `disable_rewards: true`, consuming the single per-block reward slot (by writing `last_reward_block`) without distributing any rewards. Because `last_reward_block` is a global singleton, this blocks every staker from receiving consensus block rewards for that block. Repeated every block, this permanently freezes all consensus-phase yield.

### Finding Description
`update_rewards` in `src/staking/staking.cairo` is the consensus-phase reward distribution entry point. Its only guards are `general_prerequisites()` (unpaused + non-zero caller) and a per-block deduplication check:

```cairo
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
    ...
    // Update last block rewards.
    self.last_reward_block.write(current_block_number);   // ← written unconditionally

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits before distributing rewards
    }
    ...
``` [1](#0-0) 

The critical sequence is:
1. `last_reward_block` is written to `current_block_number` **before** the `disable_rewards` branch.
2. If `disable_rewards == true`, the function returns immediately — no rewards are calculated or transferred.
3. Any subsequent call to `update_rewards` in the same block hits `REWARDS_ALREADY_UPDATED` and reverts.

There is no check that the caller is the staker, the staker's operational address, or any privileged role. The `general_prerequisites()` helper only asserts the contract is unpaused and the caller is non-zero. [2](#0-1) 

`last_reward_block` is a single global storage slot shared across all stakers: [3](#0-2) 

### Impact Explanation
An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` as the first transaction in every block will:
- Consume the per-block reward slot for the entire protocol.
- Prevent every staker from receiving consensus block rewards indefinitely.

This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators in the consensus phase. The attacker gains nothing financially, but the protocol's entire consensus reward stream is silenced. This falls under the allowed High impact: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

### Likelihood Explanation
- No privileged role, key, or special condition is required — any non-zero address suffices.
- The attacker only needs to know one valid, active staker address (all staker addresses are public on-chain via the `stakers` vector and emitted `NewStaker` events).
- On Starknet, transaction fees are low, making sustained per-block griefing economically viable.
- The attack is reachable immediately once the protocol enters the consensus phase (`consensus_rewards_first_epoch` is set).

### Recommendation
Restrict `update_rewards` to the staker's registered operational address (or the staker address itself). For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    let caller = get_caller_address();
    let staker_info = self.internal_staker_info(:staker_address);
    assert!(
        caller == staker_address || caller == staker_info.operational_address,
        "{}",
        Error::CALLER_IS_NOT_STAKER_OR_OPERATIONAL,
    );
    ...
```

Alternatively, restrict it to the attestation contract or a dedicated rewards-manager role, consistent with how `update_rewards_from_attestation_contract` is guarded: [4](#0-3) 

### Proof of Concept

```
// Attacker (any address) runs this every block during consensus phase:

// 1. Pick any known active staker address (public from NewStaker events).
let victim_staker = <any_valid_staker_address>;

// 2. Call update_rewards with disable_rewards = true.
//    - last_reward_block is set to current_block_number.
//    - Function returns before distributing any rewards.
staking.update_rewards(staker_address: victim_staker, disable_rewards: true);

// 3. Any legitimate call by the real staker in the same block now reverts:
//    "REWARDS_ALREADY_UPDATED"
staking.update_rewards(staker_address: victim_staker, disable_rewards: false);
// → panics: REWARDS_ALREADY_UPDATED

// Repeated every block → all stakers receive zero consensus rewards indefinitely.
```

The root cause is at: [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

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

**File:** src/staking/staking.cairo (L1449-1489)
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
