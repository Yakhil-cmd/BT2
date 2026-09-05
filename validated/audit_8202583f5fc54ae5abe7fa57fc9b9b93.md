### Title
Mid-cycle `unstake-sbtc` unlocks sBTC without reducing the already-published `.signers` weight for the currently active reward cycle - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`unstake-sbtc` lets a staker withdraw sBTC (up to and including their full `current-amount-sats`) from the **currently active** reward cycle, not just future cycles, because `first-changed-reward-cycle` is clamped to `current-cycle` when the bond is already active. The only guard, `verify-not-prepare-phase`, blocks the call solely during the *current* cycle's prepare phase (which protects the *next* cycle's not-yet-published snapshot); it does nothing to protect the *current* cycle's already-published `.signers` weight, which was frozen one prepare-phase earlier by `pox_5_compute_and_update_signers`/`update_signers`. sBTC is transferred back to the staker immediately while that stale, higher weight remains live for the rest of the cycle.

### Finding Description
The equality that must hold for the duration of reward cycle `N` is:

```
.signers weight for signer S at cycle N  ==  sats actually still locked by S's stakers for cycle N
```

That weight is written exactly once, during cycle `N-1`'s prepare phase, by `pox_5_compute_and_update_signers` -> `update_signers`, which reads `get-amount-delegated-for-signer` at that block height and pushes the resulting `weight`/`stacked_amt` into the `.signers` contract [1](#0-0) . `check_and_handle_prepare_phase_start` only re-runs this snapshot once per cycle, gated by `SIGNERS_UPDATE_STATE` [2](#0-1) . Consensus code (`get_signers_weights`) reads that frozen tuple verbatim for the whole cycle [3](#0-2) .

In `unstake-sbtc`, `first-changed-reward-cycle` is `(clamp current-cycle bond-start-cycle bond-end-cycle)` - i.e. it equals the **currently active** cycle whenever the bond is already running [4](#0-3) . The only phase guard is `verify-not-prepare-phase`, which rejects the call solely while the current cycle is in *its own* prepare phase (i.e. while the **next** cycle's `.signers` snapshot is being computed) [5](#0-4) . This is confirmed by the regression comment/test for stacks-network/stacks-core#7295, which explicitly frames the fix as protecting the *next-cycle, frozen-during-prepare-phase* snapshot, not the currently active cycle's already-published entry [6](#0-5) .

Outside the prepare-phase window (i.e., for essentially the entire cycle `N`), `unstake-sbtc` -> `unstake-sats-from-bond-cycles` -> `unstake-sats-from-bond-cycle` reduces `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and `staker-shares-staked-for-cycle` for `reward-cycle = N` (the current cycle) down to `new-amount-sats` (which can be `u0` for a full withdrawal) [7](#0-6) , and then immediately transfers the sBTC back to the staker via `as-contract? ... sbtc-token transfer` [8](#0-7) .

Critically, none of `unstake-sbtc`'s mutations touch `signer-delegated-per-cycle`, the map backing `get-amount-delegated-for-signer` that `pox_5_stake_entries` (via `StakeEntryIteratorPox5`) reads to build the weight fed into `pox_5_make_signer_set` [9](#0-8) . Only the bond-scoped maps (`*-shares-staked-for-cycle` with `bond-index: (some bond-index)`) are updated. This means the discrepancy is not limited to the remainder of the current cycle by snapshot-timing alone - it also risks not self-correcting at the next prepare-phase recomputation for `N+1`, since the aggregate figure the weight calculation actually reads may never be decremented by `unstake-sbtc`. (I was not able to fully trace every writer of `signer-delegated-per-cycle` in the time available, so this compounding effect is noted as unconfirmed, but the primary in-cycle mismatch is fully confirmed by direct code reading.)

**Attacker's exact call:** an sBTC bond participant (unprivileged, own funds) calls `(contract-call? .pox-5 unstake-sbtc signer-manager-trait current-amount-sats)` at any burn height inside the current, already-snapshotted cycle that is not in the current cycle's prepare-phase window.

**Why existing guards fail:** `verify-not-prepare-phase`, `validate-no-reentrancy`, and the `<=` amount guard all check unrelated invariants (next-cycle mutation timing, reentrancy, and withdrawal-amount bound respectively) - none of them re-check or re-publish the `.signers` weight for the cycle being mutated.

### Impact Explanation
For the remainder of reward cycle `N`, the `.signers` contract continues to report a `weight`/`stacked_amt` for the affected signer that is backed by less (potentially zero, for a full withdrawal) actual locked sBTC than what was published. This is a "signing weight ... exceeding locked value" condition (High severity per the stated categories): the signer's published cryptographic authority for verifying/countersigning Nakamoto blocks for the rest of cycle `N` is not fully backed by locked collateral. The staker who unstaked suffers no loss (they get their sBTC back as designed); the harm is to the protocol's collateralization guarantee for the signer set during the remainder of the live cycle. This is repeatable by any sBTC bond participant, once per staker per cycle (bounded by their own custodied sats), and does not require any privileged role.

### Likelihood Explanation
Preconditions are all attacker-controlled and cheap: be an sBTC bond participant (`register-for-bond`) for a signer, wait until the cycle is active and not in the last `pox-prepare-cycle-length` blocks of that cycle (the vast majority of a reward cycle), and call `unstake-sbtc` with `amount-to-withdrawal-sats` up to `current-amount-sats`. No coordination with the signer, admin, or other privileged party is required. The only cost is normal transaction fees. This is directly reachable and repeatable every cycle a bond is active.

### Recommendation
Either (a) forbid `unstake-sbtc` (and `unstake-sats-from-bond-cycles`) from touching the *currently active* reward cycle at all - i.e. clamp changes to start no earlier than `current-cycle + 1`, matching how `.signers` snapshots are only mutable for the next, not-yet-published cycle - or (b) if intra-cycle sBTC withdrawal must remain supported, add a mechanism to re-publish/adjust the `.signers` weight for the current cycle (or otherwise cap effective signing weight to currently-locked value) whenever `unstake-sbtc` reduces `current-amount-sats` mid-cycle. Additionally, verify and, if missing, wire `unstake-sbtc`'s bond-scoped reductions into `signer-delegated-per-cycle` so future prepare-phase recomputations correctly reflect reduced sBTC bonds.

### Proof of Concept
Rust integration test (in `stacks-node/src/tests/pox_5_integrations.rs` style, alongside the existing `unstake`/`unstake-sbtc` prepare-phase tests):
1. Boot a Nakamoto chain to Epoch 3.0/PoX-5 activation, register a signer, and have a staker `register-for-bond` with a given `amountSats` and `numCycles` sufficient to make the signer cross `SIGNER_SET_MIN_USTX`/reward-slot allocation threshold.
2. Mine through the prepare phase so `pox_5_compute_and_update_signers` publishes `.signers` weight for cycle `N`.
3. Call `NakamotoSigners::get_signers_weights(..., N)` and record `weight_before` for the signer.
4. Mine into the middle of cycle `N` (outside its prepare-phase window).
5. Submit `unstake-sbtc` from the staker with `amount-to-withdrawal-sats == current-amount-sats` (full withdrawal); confirm the tx succeeds and the staker's sBTC balance increases by that amount.
6. Re-read `NakamotoSigners::get_signers_weights(..., N)` and assert `weight_after == weight_before` (i.e., unchanged), while independently reading `pox-5`'s `get-signer-shares-staked-for-cycle`/`get-total-shares-staked-for-cycle` for cycle `N` and bond-index and asserting they dropped to `0`/reduced accordingly - proving `.signers` weight no longer equals actual locked sats for cycle `N`.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L424-439)
```rust
        // Total uSTX delegated to this signer for this cycle (sums STX-only
        // staking and protocol bonds; see signer-delegated-per-cycle).
        let amount_ustx = self
            .clarity
            .eval_method_read_only(
                &self.pox_contract,
                "get-amount-delegated-for-signer",
                &[lookup_signer.clone(), self.reward_cycle_clar.clone()],
            )
            .map_err(|e| PoxEntryParsingError::Skip(e.to_string()))?
            .expect_u128()
            .map_err(|_| {
                PoxEntryParsingError::Skip(
                    "get-amount-delegated-for-signer did not return uint".into(),
                )
            })?;
```

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

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L1076-1090)
```rust
    pub fn get_signers_weights(
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
        reward_cycle: u64,
    ) -> Result<HashMap<StacksAddress, u64>, ChainstateError> {
        let signers_opt = chainstate
            .eval_boot_code_read_only(
                sortdb,
                block_id,
                SIGNERS_NAME,
                &format!("(get-signers u{reward_cycle})"),
            )?
            .expect_optional()
            .map_err(|_| ChainstateError::Expects("get-signers did not return optional".into()))?;
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1272-1283)
```text
            (current-cycle (current-pox-reward-cycle))
            (bond-start-cycle (bond-period-to-reward-cycle bond-index))
            (bond-end-cycle (bond-period-to-reward-cycle (+ bond-index u6)))
            (first-changed-reward-cycle (clamp current-cycle bond-start-cycle bond-end-cycle))
            (num-cycles (- bond-end-cycle first-changed-reward-cycle))
            (current-amount-sats (get amount-sats membership))
            (current-total-sbtc-staked (get-total-sbtc-staked))
            ;; Cannot withdrawal more than they've staked
            (new-amount-sats (try! (if (<= amount-to-withdrawal-sats current-amount-sats)
                (ok (- current-amount-sats amount-to-withdrawal-sats))
                ERR_INVALID_UNSTAKE_SBTC_AMOUNT
            )))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1317-1329)
```text
        ;; Mutate the total sBTC staked
        (var-set total-sbtc-staked
            (- current-total-sbtc-staked amount-to-withdrawal-sats)
        )

        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" amount-to-withdrawal-sats
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer amount-to-withdrawal-sats tx-sender staker none
            ))
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1368-1420)
```text
(define-private (unstake-sats-from-bond-cycle
        (cycle-index uint)
        (accumulator-res (response {
            staker: principal,
            bond-index: uint,
            first-reward-cycle: uint,
            amount-to-withdrawal-sats: uint,
            new-amount-sats: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (reward-cycle (+ cycle-index (get first-reward-cycle accumulator)))
            (staker (get staker accumulator))
            (bond-index (get bond-index accumulator))
            (amount-to-withdrawal-sats (get amount-to-withdrawal-sats accumulator))
            (new-amount-sats (get new-amount-sats accumulator))
            (signer (get signer
                (unwrap! (get-signer-cycle-membership staker reward-cycle)
                    ERR_NOT_STAKING
                )))
            (current-total-staked (get-total-shares-staked-for-cycle reward-cycle (some bond-index)))
            (current-signer-staked (get-signer-shares-staked-for-cycle signer reward-cycle
                (some bond-index)
            ))
        )
        (settle-rewards signer reward-cycle (some bond-index))
        (settle-staker-rewards signer reward-cycle (some bond-index) staker)
        (map-set total-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
        }
            (- current-total-staked amount-to-withdrawal-sats)
        )
        (map-set signer-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
        }
            (- current-signer-staked amount-to-withdrawal-sats)
        )
        (map-set staker-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
            staker: staker,
        }
            new-amount-sats
        )
        (ok accumulator)
    )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2952-2960)
```text
;; Reject calls that would modify the next reward cycle's signer / staker
;; set during the current cycle's prepare phase, when that set is frozen.
;; Used by `stake`, `stake-update`, `register-for-bond`, and
;; `update-bond-registration` as `(try! (verify-not-prepare-phase))`.
(define-private (verify-not-prepare-phase)
    (ok (asserts! (not (is-in-prepare-phase (current-pox-reward-cycle)))
        ERR_STAKE_IN_PREPARE_PHASE
    ))
)
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L5917-5926)
```typescript
/**
 * Regression for stacks-network/stacks-core#7295. `unstake-sbtc` mutates
 * next-cycle bond / signer shares, and the next-cycle signer set is frozen
 * during the current cycle's prepare phase. The other share-mutating
 * entry-points (`stake`, `stake-update`, `register-for-bond`,
 * `update-bond-registration`) all gate on `verify-not-prepare-phase`;
 * `unstake-sbtc` previously side-stepped it. After the fix it returns
 * `ERR_STAKE_IN_PREPARE_PHASE` mid-prepare and succeeds once the next
 * cycle starts.
 */
```
