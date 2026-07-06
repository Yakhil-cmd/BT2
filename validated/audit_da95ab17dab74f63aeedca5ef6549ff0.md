### Title
Unprivileged Caller Can Invoke `update_rewards` with `disable_rewards=true` to Permanently Freeze All Staker Consensus Yield — (File: src/staking/staking.cairo)

---

### Summary
`StakingRewardsManagerImpl::update_rewards` is a public function with no access-control guard. It accepts a caller-supplied `disable_rewards: bool` flag. Any unprivileged address can call it with `disable_rewards: true`, which advances the global `last_reward_block` cursor without distributing any rewards. Because the cursor is global and monotone, one such call per block permanently blocks all stakers from receiving consensus-mode block rewards for that block. Repeated across every block, this permanently freezes all unclaimed yield.

---

### Finding Description

`update_rewards` is exposed on the public `IStakingRewardsManager` interface: [1](#0-0) 

Its only entry guard is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero: [2](#0-1) 

After passing that guard, the function writes the current block number into the global `last_reward_block`: [3](#0-2) 

When `disable_rewards` is `true`, execution returns immediately after that write — no rewards are computed or transferred. Any subsequent call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED` because the cursor has already been advanced.

In consensus mode (after `consensus_rewards_first_epoch` is set), `update_rewards_from_attestation_contract` is gated behind `assert!(self.is_pre_consensus())` and therefore cannot be used: [4](#0-3) 

This makes `update_rewards` the sole path for distributing block rewards in consensus mode. The attestation contract itself never calls `update_rewards`: [5](#0-4) 

The analog to the `burn()` report is exact: just as the owner could destroy any user's token balance without consent, here any caller can invoke a privileged state-mutation (`disable_rewards: true`) on behalf of all stakers without their consent, with the same destructive effect on their yield.

---

### Impact Explanation

In consensus mode, `update_rewards` is the only mechanism that calls `_update_rewards` to compute and distribute block rewards to stakers and their delegation pools. An attacker who calls `update_rewards(any_staker, disable_rewards: true)` in every block prevents any rewards from ever being distributed. All stakers' unclaimed yield is permanently frozen. This matches the **High** impact category: *Permanent freezing of unclaimed yield*.

---

### Likelihood Explanation

The entry path requires no privilege, no leaked key, and no external dependency. Any EOA or contract on Starknet can call `update_rewards`. The cost is one transaction per block. The attacker needs no profit motive — a competitor, a griefing actor, or an automated bot suffices. The function is already live in the production interface.

---

### Recommendation

Restrict `update_rewards` to an authorized caller (e.g., the attestation contract address, or a dedicated `REWARDS_MANAGER` role). The simplest fix is to add a role check analogous to the existing `only_security_agent` / `only_token_admin` guards used elsewhere:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.roles.only_rewards_manager(); // add this guard
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface and handle the disable logic through a separate privileged function.

---

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and passed).
2. Attacker (any address) calls `staking.update_rewards(victim_staker, disable_rewards: true)` in block N.
3. `last_reward_block` is written to N; no rewards are distributed.
4. The legitimate caller (e.g., attestation contract or staker) attempts `update_rewards(victim_staker, disable_rewards: false)` in the same block N → reverts with `REWARDS_ALREADY_UPDATED`. [6](#0-5) 

5. Attacker repeats step 2 in every subsequent block.
6. Result: `_update_rewards` is never reached in consensus mode; all stakers accumulate zero new rewards indefinitely.

### Citations

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

**File:** src/staking/staking.cairo (L1394-1400)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
```

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/attestation/attestation.cairo (L116-135)
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
        }
```
