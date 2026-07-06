### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the `StakingRewardsManagerImpl` implementation is callable by any address, despite the protocol specification explicitly requiring it to be restricted to "Only starkware sequencer." An unprivileged attacker can call this function every block with `disable_rewards: true`, consuming the per-block reward slot and permanently preventing legitimate reward distribution to all stakers and their delegators.

### Finding Description

The `IStakingRewardsManager::update_rewards` function is exposed publicly with no caller restriction. The spec at `docs/spec.md` line 1645 states its access control is "Only starkware sequencer," but the implementation contains no such check.

The function uses a single global `last_reward_block` storage variable. Once `update_rewards` is called for any staker in a given block, `last_reward_block` is updated to that block number. Any subsequent call in the same block — including the legitimate sequencer call — will fail with `REWARDS_ALREADY_UPDATED`.

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
    // ... no caller identity check ...
    self.last_reward_block.write(current_block_number);  // consumes the block slot

    if disable_rewards || self.is_pre_consensus() {
        return;  // returns without distributing rewards
    }
    // ... reward distribution ...
}
``` [1](#0-0) [2](#0-1) 

The `last_reward_block` is a single global field, not per-staker: [3](#0-2) 

The interface definition confirms the function is part of the public ABI with no documented caller restriction in the interface itself: [4](#0-3) 

### Impact Explanation

An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` on every new block. This:

1. Passes all precondition checks (staker exists, block is new, contract not paused).
2. Writes `current_block_number` to `last_reward_block`, consuming the block's reward slot.
3. Returns early due to `disable_rewards: true` — **no rewards are distributed**.
4. The legitimate sequencer's call for the same block fails with `REWARDS_ALREADY_UPDATED`.

Every staker and every pool member permanently stops accumulating `unclaimed_rewards_own` / pool rewards. This constitutes **permanent freezing of unclaimed yield** for the entire protocol.

Additionally, the attacker can call with `disable_rewards: false` to selectively grant rewards to a chosen staker, manipulating which staker benefits from each block's reward budget.

### Likelihood Explanation

The function is publicly callable with no authentication. The only cost to the attacker is gas per block. There is no economic barrier. The attack is trivially scriptable and can be sustained indefinitely. Any motivated griever — including a competing validator — can execute it.

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the configured Starkware sequencer address (analogous to how `update_rewards_from_attestation_contract` checks `assert_caller_is_attestation_contract()`):

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.assert_caller_is_sequencer(); // add this
    self.general_prerequisites();
    ...
}
```

Store the sequencer address in contract storage (set at construction/config time) and expose a governance-gated setter, mirroring the pattern used for `attestation_contract`. [5](#0-4) 

### Proof of Concept

```cairo
// Attacker script: call once per block to freeze all yield
fn attack(staking: IStakingRewardsManagerDispatcher, any_staker: ContractAddress) {
    // No special role needed. Called by any address.
    staking.update_rewards(staker_address: any_staker, disable_rewards: true);
    // last_reward_block is now set to current block.
    // Sequencer's legitimate call for this block will revert with REWARDS_ALREADY_UPDATED.
    // No staker or delegator accrues rewards for this block.
}
```

The attacker repeats this every block. After `K` epochs, all stakers' `unclaimed_rewards_own` remain at zero and all pool `cumulative_rewards_trace` entries stop growing, permanently freezing yield for every participant in the protocol.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1392-1402)
```text
    #[abi(embed_v0)]
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
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

**File:** docs/spec.md (L1638-1646)
```markdown
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
