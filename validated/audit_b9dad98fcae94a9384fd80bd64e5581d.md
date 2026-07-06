### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Block Rewards - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in the `StakingRewardsManagerImpl` is exposed as a public external entry point (`#[abi(embed_v0)]`) but contains **no check that the caller is the Starkware sequencer**, despite the specification explicitly requiring "Only starkware sequencer" access control. Any unprivileged address can call this function with `disable_rewards: true` to consume the per-block reward slot without distributing rewards, permanently denying stakers their block rewards for that block.

---

### Finding Description

The specification at `docs/spec.md` lines 1626–1652 defines `update_rewards` with the access control:

> **Only starkware sequencer.**

The implementation at `src/staking/staking.cairo` lines 1447–1508 exposes this function via `#[abi(embed_v0)]` (making it a public external call) and performs only these checks:

1. `self.general_prerequisites()` — contract is not paused
2. `current_block_number > self.last_reward_block.read()` — rewards not yet updated this block
3. Staker exists and is active
4. Staker has non-zero balance

There is **no `get_caller_address()` check** against a stored sequencer address. Compare this to analogous privileged functions in the same codebase — `update_rewards_from_attestation_contract` calls `self.assert_caller_is_attestation_contract()` [1](#0-0) , and `update_current_epoch_block_rewards` in the reward supplier asserts `get_caller_address() == staking_contract` [2](#0-1) . No equivalent guard exists in `update_rewards`. [3](#0-2) 

The `last_reward_block` is a **single global slot** (not per-staker). Once written for the current block, the guard `current_block_number > self.last_reward_block.read()` causes every subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 

The interface definition confirms the function is part of the public ABI: [5](#0-4) 

The spec access control requirement is documented here: [6](#0-5) 

---

### Impact Explanation

An attacker calls `update_rewards(staker_address: <any_valid_active_staker>, disable_rewards: true)` once per block, every block.

- `last_reward_block` is set to the current block number.
- The function returns early at line 1487 without distributing any rewards (`disable_rewards` is `true`).
- The legitimate sequencer call for the same block reverts with `REWARDS_ALREADY_UPDATED`.
- The block rewards that should have been credited to `unclaimed_rewards_own` are **never minted or recorded** — they are permanently lost.

Sustained over time, this permanently freezes all unclaimed block-reward yield for all stakers. This matches the allowed impact: **Permanent freezing of unclaimed yield.** [7](#0-6) 

---

### Likelihood Explanation

- The function is publicly callable by any EOA or contract on Starknet — no special role, key, or privilege is required.
- The attacker only needs to know one valid, active staker address (publicly observable from `NewStaker` events).
- The gas cost of calling `update_rewards(..., disable_rewards: true)` is low; the attacker has no profit motive but can cause sustained damage at minimal cost.
- The attack is repeatable every block with no cooldown.

---

### Recommendation

Add a caller check at the top of `update_rewards` that asserts the caller is the stored Starkware sequencer address, consistent with the spec and analogous to the guard used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.assert_caller_is_sequencer(); // <-- add this
    self.general_prerequisites();
    ...
}
```

Store the sequencer address in contract storage (set at construction/configuration time) and expose a setter gated by an appropriate admin role, mirroring the pattern used for `attestation_contract`. [8](#0-7) 

---

### Proof of Concept

```
// Any unprivileged address executes this every block:
IStakingRewardsManagerDispatcher { contract_address: staking_contract }
    .update_rewards(
        staker_address: <any_valid_active_staker>,
        disable_rewards: true,   // no rewards distributed
    );
// Result: last_reward_block = current_block
// Sequencer's subsequent call for the same block reverts: REWARDS_ALREADY_UPDATED
// Block rewards for this block are permanently lost for all stakers.
```

The existing test suite confirms `update_rewards` is callable without any caller restriction — `test_update_rewards_only_staker` calls it directly from an arbitrary test address with no role setup: [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L1392-1401)
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
```

**File:** src/staking/staking.cairo (L1447-1508)
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

**File:** src/reward_supplier/reward_supplier.cairo (L167-172)
```text
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
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

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/tests/test.cairo (L3488-3527)
```text
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
