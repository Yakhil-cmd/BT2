### Title
Full sBTC withdrawal via `unstake-sbtc` leaves already-published `.signers` weight for the current reward cycle unbacked - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`unstake-sats-from-bond-cycles`, like the other cycle-mutation helpers in `pox-5.clar` (e.g. `update-bond-registration`'s `first-reward-cycle` computation), only zeroes `signer-delegated-per-cycle` / `bondStakerSharesForCycle` starting at a `first-changed-reward-cycle` that is the *next* reward cycle, deliberately leaving the already-locked-in current cycle's per-cycle accounting untouched. However, the sBTC transfer back to the staker in `unstake-sbtc` is not gated on cycle boundaries the same way: the `sbtc-token transfer` executes immediately regardless of whether the current cycle's weight entry has been reduced. This creates a window, for the remainder of the current cycle, where the `.signers` contract's already-published `weight`/`stacked_amt` (written by `NakamotoSigners::update_signers` during `pox_5_compute_and_update_signers` at prepare-phase start) continues to reflect sats that have since been physically transferred out of custody.

### Finding Description
The equality that must hold is: **sats recorded as backing a signer's weight in `.signers` for reward cycle `N`** == **sats actually still custodied by pox-5 for that signer/staker at cycle `N`**.

- At prepare-phase start for cycle `N`, `NakamotoSigners::check_and_handle_prepare_phase_start` calls `pox_5_compute_and_update_signers`, which reads `pox-5`'s per-cycle stake entries and writes an immutable `weight`/`stacked_amt` snapshot into the `.signers` contract via `update_signers` [1](#0-0) . This snapshot is what block-signature verification uses for the remainder of cycle `N`; there is no mechanism to update it again until the next prepare phase (`SIGNERS_UPDATE_STATE` gate) [2](#0-1) .
- Inside `pox-5.clar`, mutation helpers that touch per-cycle maps (`signer-delegated-per-cycle`, `bondStakerSharesForCycle`/`staker-shares-staked-for-cycle`) compute a "first changed cycle" as `current-cycle + 1` when adjusting a live participant, exactly as seen in `update-bond-registration`'s `first-reward-cycle (clamp next-cycle bond-start-cycle bond-end-cycle)` [3](#0-2) . This convention is what prevents *retroactive* weight edits for a cycle whose `.signers` snapshot is already finalized. `unstake-sats-from-bond-cycles` follows the same pattern for the per-cycle delegation maps.
- The flaw is that `unstake-sbtc`'s custody transfer is not similarly deferred: the sBTC is sent back to the staker as soon as the call executes, not gated to occur only after the current cycle's already-published weight has rolled over. So the staker can withdraw the physical sBTC immediately while `signer-delegated-per-cycle`/`bondStakerSharesForCycle` for the *current* (already-locked-in) cycle intentionally still reports the old, pre-withdrawal amount.
- Attacker's call: an sBTC bond participant simply calls `unstake-sbtc` with `amount-to-withdrawal-sats` equal to their full `current-amount-sats` mid-cycle, after `.signers` has already been finalized for that cycle (`SIGNERS_UPDATE_STATE >= current cycle`).
- None of the existing guards stop this: `verify-not-prepare-phase` only blocks calls during the prepare phase (i.e. while the *next* cycle's snapshot is being computed), not calls during the already-active current cycle; `validate-no-reentrancy`/`signer-manager-call-active` guards against reentrancy, not against premature custody release; there is no `check-pox-lock-period`-style assertion in `unstake-sbtc` tying the sBTC release to the cycle-rollover of the per-cycle delegation maps.

### Impact Explanation
For the remainder of the current reward cycle, the signer's `weight`/`stacked_amt` published in `.signers` exceeds the sats actually still custodied by pox-5 for that signer, i.e. a case of **signing weight/reward slots exceeding locked value** (High severity per the given rubric). The affected party is the protocol/network (signature verification integrity), not a direct fund theft from another user — the staker recovers only their own sBTC, but the signer's published weight is left artificially inflated relative to real backing for up to a full cycle. This is repeatable every cycle by any bond participant who unstakes mid-cycle rather than waiting for the cycle boundary.

### Likelihood Explanation
Preconditions: attacker must be an existing sBTC bond participant (self-controlled, no privileged role needed), and the call must occur after `.signers` has been finalized for the current cycle (true for almost the entire non-prepare-phase portion of every cycle) and outside the prepare phase (`verify-not-prepare-phase` only blocks the last portion of the cycle). Cost is a single `unstake-sbtc` transaction; feasibility is high since it requires no coordination with the signer, bond admin, or any other privileged actor, and is fully repeatable across cycles/bonds.

### Recommendation
Gate the sBTC transfer in `unstake-sbtc` the same way the per-cycle maps are gated: only release the portion of `current-amount-sats` that exceeds what is still committed for the current (already-published) cycle immediately, and defer release of the current-cycle-committed remainder until after the cycle rolls over (i.e., mirror `first-changed-reward-cycle` for the custody release, not just for the delegation-map zeroing). Alternatively, reduce `signer-delegated-per-cycle`/`bondStakerSharesForCycle` for the current cycle in lockstep with any sBTC released for that cycle, and have the node-side signer-weight calculation account for such reductions (or block them) rather than relying purely on the prepare-phase snapshot.

### Proof of Concept
Rust integration test outline:
1. Boot a chain through Epoch 3.0 with pox-5 active; create a bond and stake sBTC via `register-for-bond` for a signer `S`.
2. Advance to the prepare phase of cycle `N`, triggering `check_and_handle_prepare_phase_start` -> `pox_5_compute_and_update_signers` -> `update_signers`, and read `.signers`' weight/`stacked_amt` for `S` at cycle `N` via `NakamotoSigners::get_signers_weights` — call this `W_before`.
3. Advance a few blocks into cycle `N` (past the prepare phase, `SIGNERS_UPDATE_STATE >= N`).
4. Call `unstake-sbtc` from the staker for `amount-to-withdrawal-sats == current-amount-sats` (full withdrawal), and assert the `sbtc-token transfer` succeeds (staker's sBTC balance increases by the withdrawn amount, contract custody decreases).
5. Re-read `.signers` weight/`stacked_amt` for cycle `N` for signer `S` — assert it is unchanged (`== W_before`), while the sBTC now actually custodied for that staker/cycle is `0`, demonstrating the equality break: published weight for cycle `N` no longer equals sats actually locked.
6. Additionally assert that at the *next* prepare phase (cycle `N+1`), the newly recomputed `.signers` weight correctly reflects the reduction, confirming the divergence is confined to (but real during) the remainder of cycle `N`.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L744-776)
```rust
    fn pox_5_compute_and_update_signers(
        clarity: &mut ClarityTransactionConnection,
        pox_constants: &PoxConstants,
        reward_cycle: u64,
        pox_contract: &str,
        coinbase_height: u64,
        _current_calculation_btc_height: u32,
        _current_epoch: &StacksEpochId,
    ) -> Result<SignerCalculation, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        // Build the `(signer_key, amount_ustx)` pair stream
        let mut entries = Self::pox_5_stake_entries(clarity, reward_cycle, pox_contract)?;
        let Pox5SignerSetOutput {
            signer_set,
            pox_ustx_threshold,
        } = Self::pox_5_make_signer_set(&mut entries, pox_constants)?;

        if signer_set.is_empty() {
            error!("Fatal network condition: reward set computed with an empty signer set. Cannot continue producing blocks");
            return Err(ChainstateError::PoxNoRewardCycle);
        }

        let events = Self::update_signers(
            clarity,
            reward_cycle,
            &signer_set,
            signers_contract,
            signer_set.len() > 0,
            coinbase_height,
            is_mainnet,
        )?;
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L991-1022)
```rust
        let signers_contract = &boot_code_id(SIGNERS_NAME, clarity_tx.config.mainnet);

        // are we the first block in the prepare phase in our fork?
        let needs_update_result: Result<_, ChainstateError> = clarity_tx
            .connection()
            .with_clarity_db_readonly(|clarity_db| {
                if !clarity_db.has_contract(signers_contract) {
                    // if there's no signers contract, no need to update anything.
                    return Ok(false);
                }
                let value = clarity_db.lookup_variable_unknown_descriptor(
                    signers_contract,
                    SIGNERS_UPDATE_STATE,
                    &current_epoch,
                )?;
                let cycle_number = value.expect_u128().map_err(|_| {
                    ChainstateError::Expects(format!(
                        "Expected u128 for .signers {SIGNERS_UPDATE_STATE} variable"
                    ))
                })?;
                // if the cycle_number is less than `cycle_of_prepare_phase`, we need to update
                //  the .signers state.
                let needs_update = cycle_number < u128::from(cycle_of_prepare_phase);
                Ok(needs_update)
            });

        let needs_update = needs_update_result?;

        if !needs_update {
            debug!("Current cycle has already been setup in .signers or .signers is not initialized yet");
            return Ok(None);
        }
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L861-870)
```text
            (current-cycle (current-pox-reward-cycle))
            (bond-start-cycle (bond-period-to-reward-cycle bond-index))
            (bond-end-cycle (bond-period-to-reward-cycle (+ bond-index u6)))
            (next-cycle (+ current-cycle u1))
            ;; If the bond hasn't started yet, then the first cycle where
            ;; this new signer is active is the start cycle. Otherwise, it's the next reward
            ;; cycle, unless the bond will be over at that point.
            (first-reward-cycle (clamp next-cycle bond-start-cycle bond-end-cycle))
            (amount-sats (get amount-sats current-membership))
            (num-cycles (- bond-end-cycle first-reward-cycle))
```
