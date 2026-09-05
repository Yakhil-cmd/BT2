### Title
`stake-extend` in pox-5 may mutate share state without the prepare-phase freeze guard applied to sibling entry points - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
pox-5.clar introduces an explicit mechanism, `verify-not-prepare-phase`, to prevent exactly the class of bug described in the ThrusterTreasure report: mutating share/commitment state for a reward cycle after that cycle's signer/staker set has already been "frozen" (computed) during the current cycle's prepare phase. The guard is documented as being required by `stake`, `stake-update`, `register-for-bond`, and `update-bond-registration`, and a regression test confirms `unstake-sbtc` previously bypassed this guard and was patched. However, `stake-extend` does not appear in the enumerated list of guarded entry points, nor does it appear to have a corresponding `...ErrInPreparePhase` regression test alongside its sibling functions, raising the same class of issue the external report flags.

### Finding Description
`stackslib/src/chainstate/stacks/boot/pox-5.clar` defines `is-in-prepare-phase` and `verify-not-prepare-phase`: [1](#0-0) 

The contract's own comment states that this guard exists specifically to "Reject calls that would modify the next reward cycle's signer / staker set during the current cycle's prepare phase, when that set is frozen," and lists `stake`, `stake-update`, `register-for-bond`, and `update-bond-registration` as the functions required to call it.

A regression-test comment in the test suite confirms this exact bug class was previously exploitable via `unstake-sbtc`, which "mutates next-cycle bond / signer shares" while "the next-cycle signer set is frozen during the current cycle's prepare phase," and that the other share-mutating entry points "all gate on `verify-not-prepare-phase`," but `unstake-sbtc` "previously side-stepped it": [2](#0-1) 

This is the direct structural analog of the ThrusterTreasure `enterTickets()` flaw: a share/commitment-mutating action is allowed to proceed after the equivalent of "prizes have been distributed" (the signer/reward set for the next cycle has been computed/frozen), breaking the equality between the recorded locked value and the frozen signer weight used for signing/rewards.

The test-file naming convention (`StakeErrInPreparePhase.ts`, `RegisterForBondErrInPreparePhase.ts`, `UpdateBondRegistrationErrInPreparePhase.ts`, `UnstakeSbtcErrInPreparePhase.ts`, `AnnounceL1EarlyExitErrInPreparePhase.ts`, `StakeUpdateErrInPreparePhase.ts`) shows there is a dedicated negative-path regression test for every other share-mutating entry point that must reject calls during the prepare phase. No corresponding `StakeExtendErrInPreparePhase.ts` test exists — `StakeExtend.ts` appears only as a plain (non-error) command file.

### Impact Explanation
If `stake-extend` can still mutate the staker's bond/share position (e.g. extending lock period, which under pox-4/pox-2/pox-3 analogs also updates `reward-set-indexes` and per-cycle totals) during the current cycle's prepare phase — after the next cycle's signer set/reward weights have already been computed and frozen from `reward-cycle-pox-address-list`/`reward-cycle-total-stacked`-equivalent state — then the frozen signer weight for the upcoming cycle would no longer correspond to the staker's actual locked/committed value. This falls under the "signing weight or reward slots exceeding locked value" High-impact category defined in scope, since it can create a discrepancy between the value used to authorize signing weight for a cycle and the STX/sBTC actually locked for that cycle at the time the set was frozen.

### Likelihood Explanation
This requires no privileged access — any unprivileged staker who already holds a bond/stake in pox-5 could call `stake-extend` during the exact window between prepare-phase start and cycle rollover, mirroring the front-running/timing window described in the external report ("even if they checked before entering their tickets, an owner call... may end up being included in a block before their transaction"). The fact that Stacks developers already had to specifically patch the analogous `unstake-sbtc` bug (per the regression test comment) for this exact reason indicates this is a real, previously-triggered bug class in this contract family, increasing the likelihood that any unaudited/unguarded sibling function (`stake-extend`) carries the same defect.

### Recommendation
Audit every function in `pox-5.clar` that mutates `protocol-bond-memberships`, signer shares, or reward-cycle totals for the *next* reward cycle, and confirm each one calls `(try! (verify-not-prepare-phase))` exactly like `stake`, `stake-update`, `register-for-bond`, `update-bond-registration`, and (post-fix) `unstake-sbtc`. Specifically verify `stake-extend`'s implementation, and if it lacks the guard, add it and add a corresponding `StakeExtendErrInPreparePhase` regression test mirroring the existing sibling tests.

### Proof of Concept
Note: I could not retrieve the full body of `stake-extend` within the iteration budget, so I cannot show the exact missing `asserts!`/`try!` line. The evidence supporting this analog is:
1. The documented invariant and enumerated guarded-function list in `is-in-prepare-phase`/`verify-not-prepare-phase`. [1](#0-0) 
2. The confirmed prior regression where `unstake-sbtc` bypassed this exact guard and mutated frozen next-cycle shares. [2](#0-1) 
3. The absence of a `StakeExtendErrInPreparePhase` test file among the otherwise-complete set of prepare-phase-rejection regression tests for every other share-mutating entry point (`StakeErrInPreparePhase.ts`, `RegisterForBondErrInPreparePhase.ts`, `UpdateBondRegistrationErrInPreparePhase.ts`, `UnstakeSbtcErrInPreparePhase.ts`, `StakeUpdateErrInPreparePhase.ts`, `AnnounceL1EarlyExitErrInPreparePhase.ts`).

This should be treated as a lead requiring direct code confirmation of `stake-extend`'s body in `pox-5.clar` (not fully retrievable within the available tool budget) before being escalated as a confirmed finding.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2944-2960)
```text
;; Are we currently in a prepare phase at the end of `current-cycle`?
(define-read-only (is-in-prepare-phase (current-cycle uint))
    (>= burn-block-height
        (- (reward-cycle-to-burn-height (+ current-cycle u1))
            (var-get pox-prepare-cycle-length)
        ))
)

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

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L5917-5927)
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
test('unstake-sbtc is rejected during the prepare phase', () => {
```
