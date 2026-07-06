### Title
Staking contract pause causes permanent loss of attestation epoch rewards for stakers - (File: `src/staking/staking.cairo`, `src/attestation/attestation.cairo`)

### Summary
When the staking contract is paused, stakers cannot complete attestation because `update_rewards_from_attestation_contract` is blocked by `general_prerequisites()`. If the pause spans a staker's attestation window (which is strictly bounded by block numbers), the staker permanently loses rewards for that epoch with no recovery mechanism after unpausing.

### Finding Description
The staking contract implements a pause mechanism controlled by the security agent. When paused, all state-changing functions revert via `general_prerequisites()`.

The attestation flow in `attestation.cairo` `attest()` calls `update_rewards_from_attestation_contract` on the staking contract as its final step:

```
// attestation.cairo lines 131-134
staking_dispatcher
    .update_rewards_from_attestation_contract(
        staker_address: staking_attestation_info.staker_address(),
    );
```

The pause test at `src/staking/tests/pause_test.cairo` lines 303–312 explicitly confirms this function reverts when paused. Because `_mark_attestation_is_done` is called *before* `update_rewards_from_attestation_contract` (lines 126–134 of `attestation.cairo`), when the staking contract is paused the entire `attest()` transaction reverts atomically — the attestation is not recorded.

The attestation window is strictly bounded by block numbers in `_assert_attest_in_window`:

```
// attestation.cairo lines 241-250
let min_block = target_attestation_block + MIN_ATTESTATION_WINDOW.into();
let max_block = target_attestation_block + attestation_window.into();
assert!(
    min_block <= current_block_number && current_block_number <= max_block,
    "{}",
    Error::ATTEST_OUT_OF_WINDOW,
);
```

Once the window closes, there is no way to retroactively attest. There is no grace period, no pause-duration compensation, and no mechanism to extend the window after unpausing.

### Impact Explanation
Stakers whose attestation window falls entirely within a pause period permanently lose their epoch rewards. This is irreversible: once the epoch's attestation window closes, the rewards for that epoch are gone. This constitutes griefing with direct damage to stakers (loss of earned yield) with no profit motive, matching **Medium: Griefing with no profit motive but damage to users or protocol**.

### Likelihood Explanation
The security agent can pause the contract at any time for any duration. Attestation windows are narrow (bounded by `attestation_window` blocks, minimum `MIN_ATTESTATION_WINDOW = 11` blocks). A pause of even a few dozen blocks during an epoch can cause all stakers whose target attestation block falls in that range to permanently miss their window. This is a realistic operational scenario (e.g., emergency pause during an incident).

### Recommendation
Introduce a grace period after unpausing the staking contract during which stakers who missed their attestation window due to the pause can still attest. Alternatively, track the total pause duration per epoch and extend the attestation window accordingly, or allow the attestation contract to record a "pause-excused" attestation for affected stakers.

### Proof of Concept
1. Staker A has a target attestation block `X` for epoch `E`. Their valid window is `[X + 11, X + attestation_window]`.
2. Security agent calls `pause()` on the staking contract at block `X + 11`.
3. Staker A calls `attest(block_hash)` on the attestation contract.
4. `attest()` reaches `staking_dispatcher.update_rewards_from_attestation_contract(...)`.
5. The staking contract reverts with `"Contract is paused"` — confirmed by `test_update_rewards_from_attestation_contract_when_paused` in `src/staking/tests/pause_test.cairo` lines 303–312.
6. The entire `attest()` transaction reverts; `staker_last_attested_epoch` is NOT updated.
7. Security agent calls `unpause()` at block `X + attestation_window + 1`.
8. Staker A retries `attest()`. `_assert_attest_in_window` now fails: `current_block_number > max_block`.
9. Staker A permanently loses all rewards for epoch `E` with no recourse. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** src/staking/tests/pause_test.cairo (L303-312)
```text
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

**File:** src/staking/staking.cairo (L136-136)
```text
        is_paused: bool,
```
