### Title
Stakers Permanently Lose Epoch Attestation Rewards When Staking Contract Is Paused During Their Attestation Window — (`src/attestation/attestation.cairo`, `src/staking/staking.cairo`)

---

### Summary
When the staking contract is paused, stakers cannot complete attestation because `attest()` in the Attestation contract calls `update_rewards_from_attestation_contract` on the staking contract, which reverts with `CONTRACT_IS_PAUSED`. The attestation window is strictly time-bounded per epoch. If the pause spans a staker's attestation window, the window expires and the staker permanently loses all epoch rewards — with no mechanism to recover them after unpause.

---

### Finding Description

The `attest()` function in `src/attestation/attestation.cairo` performs three steps in a single atomic transaction:

1. Validates the attestation (block hash, window check)
2. Marks attestation as done in `staker_last_attested_epoch`
3. Calls `update_rewards_from_attestation_contract` on the staking contract [1](#0-0) 

Step 3 calls `general_prerequisites()` inside the staking contract, which enforces the pause guard: [2](#0-1) 

Because the entire `attest()` call is one transaction, the revert from `update_rewards_from_attestation_contract` rolls back the entire call — including the `_mark_attestation_is_done` write. The staker's attestation is not recorded.

The attestation window is strictly bounded per epoch. A staker can only attest within blocks `[target_attestation_block + MIN_ATTESTATION_WINDOW, target_attestation_block + attestation_window]`: [3](#0-2) 

The `attestation_window` is a governance-set parameter (minimum 11 blocks), and the target block is pseudo-randomly assigned per staker per epoch. If the pause covers the staker's window, the window expires and the staker cannot retroactively attest in a future block or future epoch. The rewards for that epoch are permanently unclaimable.

The pause/unpause mechanism itself has no grace period or epoch-skip logic: [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

For every epoch where the staking contract is paused during a staker's attestation window, that staker permanently loses the attestation rewards for that epoch. The loss is irreversible: there is no retroactive attestation mechanism, no compensation path, and no epoch replay. The rewards are simply never credited to `unclaimed_rewards_own`. This matches the allowed impact: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

---

### Likelihood Explanation

**Medium.** Pauses are an expected operational event (triggered by the security agent for any security concern). Epochs have a fixed length and each staker has a narrow, pseudo-randomly assigned attestation window within the epoch. A pause of even moderate duration (covering the attestation window, which is as small as 11 blocks) is sufficient to cause permanent reward loss for affected stakers. The staker has no recourse — they cannot front-run the pause or take any protective action.

---

### Recommendation

After the staking contract is unpaused, record the epoch(s) during which the contract was paused. For any staker whose attestation window fell entirely within a paused period, either:
- Allow a grace attestation in the next available window without penalizing the missed epoch, or
- Automatically credit the staker with the epoch rewards they would have earned, bypassing the attestation requirement for those epochs.

At minimum, the `unpause` function should record the timestamp/epoch of unpause so that off-chain tooling or on-chain logic can identify affected stakers.

---

### Proof of Concept

```
1. Staker stakes and is registered in the staking contract.
2. Advance to epoch N (a valid attestation epoch, past STARTING_EPOCH).
3. Security agent calls pause() on the staking contract.
   → staking contract: is_paused = true
4. Blocks advance through the staker's attestation window
   [target_attestation_block + 11, target_attestation_block + attestation_window].
5. Security admin calls unpause() on the staking contract.
   → staking contract: is_paused = false
6. Staker's operational address calls attest(block_hash) on the Attestation contract.
   → _assert_attest_in_window() reverts with ATTEST_OUT_OF_WINDOW
      because current_block > target_attestation_block + attestation_window.
7. Staker has permanently lost all attestation rewards for epoch N.
   unclaimed_rewards_own is unchanged; no recovery path exists.
```

The revert path during the pause (step 3–4) is confirmed by the existing test: [5](#0-4)

### Citations

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

**File:** src/staking/staking.cairo (L1259-1266)
```text
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
