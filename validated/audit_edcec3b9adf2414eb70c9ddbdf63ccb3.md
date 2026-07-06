Based on my investigation, I found a valid analog. The `update_rewards` function in `src/staking/staking.cairo` is specified as "Only starkware sequencer" in the spec but has **no caller check** in the implementation — any address can call it.

---

### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Staker Yield - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in the `StakingRewardsManagerImpl` is documented as callable only by the Starkware sequencer, but the implementation contains no caller validation. Any unprivileged address can call it with `disable_rewards: true`, consuming the per-block reward slot and permanently denying yield for that block to all stakers.

### Finding Description
The specification at `docs/spec.md` lines 1644–1645 states:

```
#### access control
Only starkware sequencer.
```

The implementation at `src/staking/staking.cairo` lines 1447–1507 contains no such check:

```cairo
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
        // ... no caller identity check ...
        self.last_reward_block.write(current_block_number);
        if disable_rewards || self.is_pre_consensus() {
            return;
        }
        // distribute rewards ...
    }
}
``` [1](#0-0) 

The `last_reward_block` storage variable is a **global** single value. Once it is written to `current_block_number`, the guard `current_block_number > self.last_reward_block.read()` will revert for any subsequent call in the same block, including the legitimate sequencer call. [2](#0-1) [3](#0-2) 

The spec explicitly requires this to be sequencer-only: [4](#0-3) 

### Impact Explanation
An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` at the start of every block. This:
1. Writes `last_reward_block = current_block_number`.
2. Returns early without distributing any rewards (due to `disable_rewards: true`).
3. Causes every subsequent call in that block — including the legitimate sequencer call — to revert with `REWARDS_ALREADY_UPDATED`.

Repeated every block, this **permanently freezes all unclaimed yield** for all stakers in the consensus rewards phase. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation
- Requires no special role, no leaked key, no privileged access.
- Any EOA or contract can call `update_rewards` with a valid `staker_address` and `disable_rewards: true`.
- The attack is cheap (one transaction per block) and fully griefing with no profit motive required.
- Likelihood: **High**.

### Recommendation
Add a caller check analogous to `assert_caller_is_attestation_contract` used elsewhere in the same contract:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ...
}
```

The sequencer address should be stored in contract storage and set during initialization, mirroring how `attestation_contract` is stored and checked. [5](#0-4) 

### Proof of Concept
1. Deploy the system in consensus rewards mode (`is_pre_consensus()` returns `false`).
2. At the start of each block, any address calls:
   ```cairo
   staking_rewards_dispatcher.update_rewards(
       staker_address: any_valid_staker,
       disable_rewards: true
   );
   ```
3. `last_reward_block` is set to the current block number.
4. The legitimate sequencer attempts to call `update_rewards(..., disable_rewards: false)` — it reverts with `REWARDS_ALREADY_UPDATED`.
5. No staker receives rewards for that block. Repeated every block, all yield is permanently frozen.

The existing test `test_update_rewards_only_staker` at `src/staking/tests/test.cairo` line 3488 demonstrates that any caller (no `cheat_caller_address` override) can successfully invoke `update_rewards`, confirming the absence of a caller guard. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1447-1489)
```text
    #[abi(embed_v0)]
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

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/tests/test.cairo (L3487-3527)
```text
#[test]
fn test_update_rewards_only_staker() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let staking_rewards_dispatcher = IStakingRewardsManagerDispatcher {
        contract_address: staking_contract,
    };
    let staking_config_dispatcher = IStakingConfigDispatcher { contract_address: staking_contract };
    let minting_curve_contract = cfg.reward_supplier.minting_curve_contract;
    advance_epoch_global();
    let current_epoch = staking_dispatcher.get_current_epoch();
    cheat_caller_address_once(
        contract_address: staking_contract, caller_address: cfg.test_info.app_governor,
    );
    staking_config_dispatcher.set_consensus_rewards_first_epoch(epoch_id: current_epoch + 2);
    // Advance `K` epochs to start consensus rewards.
    advance_k_epochs_global();
    stake_for_testing_using_dispatcher(:cfg);
    advance_k_epochs_global();
    let staker_address = cfg.test_info.staker_address;
    let staker_info_before = staking_dispatcher.staker_info_v1(:staker_address);
    let (strk_block_rewards, _) = calculate_current_block_rewards_v3(:minting_curve_contract);
    let staker_info_expected = StakerInfoV1 {
        unclaimed_rewards_own: strk_block_rewards, ..staker_info_before,
    };
    let mut spy = snforge_std::spy_events();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
    assert!(staker_info_after == staker_info_expected);
    // Validate StakerRewardsUpdated event.
    let events = spy.get_events().emitted_by(contract_address: staking_contract).events;
    assert_number_of_events(actual: events.len(), expected: 1, message: "update_rewards");
    assert_staker_rewards_updated_event(
        spied_event: events[0],
        :staker_address,
        staker_rewards: strk_block_rewards,
        pool_rewards: [].span(),
    );
}
```
