### Title
Staking Contract Pause Causes Permanent Loss of Epoch Rewards for Stakers — (`src/attestation/attestation.cairo`, `src/staking/staking.cairo`)

---

### Summary

When the staking contract is paused, stakers cannot submit attestations. Because the attestation window is a narrow, block-bounded range within each epoch, a pause that spans a staker's window permanently eliminates that epoch's rewards with no recovery mechanism.

---

### Finding Description

In the pre-consensus reward phase, stakers earn epoch rewards exclusively by calling `attest` on the Attestation contract within a specific block window. The `attest` function internally calls `update_rewards_from_attestation_contract` on the Staking contract:

```cairo
// src/attestation/attestation.cairo:116-134
fn attest(ref self: ContractState, block_hash: felt252) {
    ...
    self._validate_attestation(:block_hash, :staking_attestation_info);
    self._mark_attestation_is_done(...);
    staking_dispatcher
        .update_rewards_from_attestation_contract(
            staker_address: staking_attestation_info.staker_address(),
        );
}
```

`update_rewards_from_attestation_contract` begins with `self.general_prerequisites()`, which enforces the `CONTRACT_IS_PAUSED` check:

```cairo
// src/staking/staking.cairo:1394-1398
fn update_rewards_from_attestation_contract(
    ref self: ContractState, staker_address: ContractAddress,
) {
    self.general_prerequisites();  // reverts with CONTRACT_IS_PAUSED
    ...
}
```

This is confirmed by the existing test:

```cairo
// src/staking/tests/pause_test.cairo:302-312
#[test]
#[should_panic(expected: "Contract is paused")]
fn test_update_rewards_from_attestation_contract_when_paused() { ... }
```

The attestation window is a narrow block range enforced by `_assert_attest_in_window`:

```cairo
// src/attestation/attestation.cairo:241-251
fn _assert_attest_in_window(self: @ContractState, target_attestation_block: BlockNumber) {
    let attestation_window = self.attestation_window.read();
    let current_block_number = get_block_number();
    let min_block = target_attestation_block + MIN_ATTESTATION_WINDOW.into();
    let max_block = target_attestation_block + attestation_window.into();
    assert!(
        min_block <= current_block_number && current_block_number <= max_block,
        "{}", Error::ATTEST_OUT_OF_WINDOW,
    );
}
```

With `MIN_ATTESTATION_WINDOW = 11` blocks and a typical `attestation_window` of ~20 blocks, the effective window is only ~9 blocks wide. On Starknet, where blocks are produced every few seconds, a pause of even a few minutes can span the entire attestation window for all stakers whose target block falls within the pause period.

There is no grace period, no retroactive attestation, and no compensation mechanism. Once the window closes, the epoch's rewards are permanently unearnable.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Stakers lose all epoch rewards for any epoch during which the contract was paused and their attestation window passed. Since attestation is the sole mechanism for earning rewards in the pre-consensus phase, this is a complete and permanent loss of yield for the affected epoch(s). The loss scales with the number of stakers whose windows fall within the pause duration and with the size of their stake.

---

### Likelihood Explanation

The `SECURITY_AGENT` role can pause the contract at any time for legitimate reasons (emergency response, EIC upgrades). The spec explicitly documents this use case. A pause of even a few minutes is sufficient to eliminate rewards for stakers whose narrow attestation window (as few as 9 blocks) falls within that period. Given that pauses are an expected operational event and the window is narrow, this scenario is realistic and not merely theoretical.

---

### Recommendation

Introduce a grace mechanism so that stakers who were unable to attest due to a pause are not penalized:

1. **Track pause duration in epochs**: Record which epochs were fully or partially paused. Allow stakers to attest retroactively for a paused epoch within a grace window after unpause.
2. **Alternatively, skip attestation requirement for paused epochs**: When computing rewards, treat any epoch during which the contract was paused as if all stakers attested (or simply do not penalize missed attestations for those epochs).
3. **Minimum viable fix**: After `unpause`, extend the current epoch's attestation window by the number of blocks the contract was paused, so stakers whose windows were blocked still have an opportunity to attest.

---

### Proof of Concept

1. Staker S has a `target_attestation_block` of block 1000 in epoch E. Their valid attestation window is blocks [1011, 1020].
2. At block 1010, `SECURITY_AGENT` calls `pause()` on the staking contract.
3. Blocks 1011–1020 pass. Staker S attempts `attest(block_hash)` but every call reverts with `"Contract is paused"` because `update_rewards_from_attestation_contract` calls `general_prerequisites()`.
4. At block 1021, `SECURITY_ADMIN` calls `unpause()`.
5. Staker S attempts `attest(block_hash)` — now reverts with `ATTEST_OUT_OF_WINDOW` because `current_block_number (1021) > max_block (1020)`.
6. Staker S earns zero rewards for epoch E. The loss is permanent — there is no mechanism to recover the missed attestation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** src/attestation/attestation.cairo (L34-34)
```text
    pub(crate) const MIN_ATTESTATION_WINDOW: u16 = 11;
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

**File:** src/attestation/attestation.cairo (L241-251)
```text
        fn _assert_attest_in_window(self: @ContractState, target_attestation_block: BlockNumber) {
            let attestation_window = self.attestation_window.read();
            let current_block_number = get_block_number();
            let min_block = target_attestation_block + MIN_ATTESTATION_WINDOW.into();
            let max_block = target_attestation_block + attestation_window.into();
            assert!(
                min_block <= current_block_number && current_block_number <= max_block,
                "{}",
                Error::ATTEST_OUT_OF_WINDOW,
            );
        }
```

**File:** src/staking/staking.cairo (L1249-1266)
```text
    impl StakingPauseImpl of IStakingPause<ContractState> {
        fn pause(ref self: ContractState) {
            self.roles.only_security_agent();
            if self.is_paused() {
                return;
            }
            self.is_paused.write(true);
            self.emit(PauseEvents::Paused { account: get_caller_address() });
        }

        fn unpause(ref self: ContractState) {
            self.roles.only_security_admin();
            if !self.is_paused() {
                return;
            }
            self.is_paused.write(false);
            self.emit(PauseEvents::Unpaused { account: get_caller_address() });
        }
```

**File:** src/staking/staking.cairo (L1394-1399)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
```

**File:** src/staking/tests/pause_test.cairo (L302-312)
```text
#[test]
#[should_panic(expected: "Contract is paused")]
fn test_update_rewards_from_attestation_contract_when_paused() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    pause_staking_contract(:cfg);
    let staking_dispatcher = IStakingAttestationDispatcher {
        contract_address: cfg.test_info.staking_contract,
    };
    staking_dispatcher.update_rewards_from_attestation_contract(staker_address: DUMMY_ADDRESS);
}
```
