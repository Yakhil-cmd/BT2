### Title
Reward-per-share sniping in `pox-5.clar` — rewards accrued for the whole distribution window are split by the *current* share balance instead of by historical stake duration - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`calculate-rewards` in `pox-5.clar` distributes STX-only staking rewards using the exact reward-per-share pattern flagged in the external report: it divides the whole period's accrued rewards by the *current* total staked shares, then credits every staker (old and new) the same per-share rate for the whole period since the last distribution. A staker who joins with a large stake immediately before `calculate-rewards` fires can claim a full pro-rata share of rewards that accrued mostly (or entirely) before their stake existed, diluting long-term stakers exactly like the BellumNursery PoC.

### Finding Description
`calculate-rewards` computes the STX-only reward increment as: [1](#0-0) 

`cycle-staked-ustx` is read via `get-total-shares-staked-for-cycle` for the *current* cycle at the moment the distribution runs — it is not a time-weighted or snapshot value taken at the start of the accrual window. `gross-accrued-rewards` (`get-new-rewards`) represents all reward tokens that flowed into the contract since `last-reward-compute-height`, i.e., potentially the whole reward cycle: [2](#0-1) 

The resulting `cumulative-rewards-per-ustx` accumulator is stored per-cycle, and every staker's claim is computed purely from the delta between the accumulator and their last-settled snapshot, scaled by their *currently recorded* shares: [3](#0-2) 

`settle-rewards` documents that it must run before any change to `signer-shares-staked-for-cycle`/`staker-shares-staked-for-cycle`, which correctly stops a staker from *retroactively* claiming credit for periods before their settled snapshot was taken: [4](#0-3) 

However, this per-user snapshot only prevents a user from claiming rewards *already baked into the accumulator before they staked*. It does not prevent a user from staking right before the *next* `calculate-rewards` call and receiving full credit for the entire elapsed period's `accrued-rewards-per-ustx` increment, because that increment is spread across whatever `cycle-staked-ustx` is at calculation time, not weighted by how long each unit of stake was actually present during the accrual window. This is structurally identical to the reported bug: `rewardsPerShare = rewards * PRECISION / totalShares` computed against the current total, seen in the test helper mirroring the contract's own math: [5](#0-4) 

### Impact Explanation
This breaks the equality that reward-per-share owed to a staker should reflect the amount of value actually locked for the duration rewards accrued. A large, short-duration staker can claim STX-staker rewards that rightfully belong (on a time-weighted basis) to long-term stakers who kept STX locked while the sBTC/reward inflows accumulated — i.e., "rewards paid that were not earned" by the sniper, at the direct expense of legitimate long-term stakers' unclaimed balances. No STX/sBTC is minted out of thin air and no funds are frozen, so this falls at most under the High-impact category ("reward slots... exceeding locked value" analog) rather than Critical, since total distributed rewards are still conserved — only misallocated among current stakers.

### Likelihood Explanation
`calculate-rewards` is a permissionless, callable-by-anyone function gated only by a half-cycle boundary check (`ERR_DISTRIBUTION_ALREADY_COMPUTED`), so an attacker can monitor incoming reward transfers, wait for a large `gross-accrued-rewards` balance to build up, and time a large `stake` call immediately before triggering (or waiting for someone else to trigger) the next `calculate-rewards`. Exploitability ultimately hinges on whether `stake`/`stack-stx`-style entry into `staker-shares-staked-for-cycle`/`signer-shares-staked-for-cycle` for the *currently accruing* cycle can happen at any point within the cycle (not only at cycle boundaries) — I was not able to fully confirm the exact timing constraints of the `stake` entry point within the indexed context before running out of search budget, so this should be verified directly against the `stake` function in `pox-5.clar` before treating this as confirmed-exploitable rather than a design-level risk.

### Recommendation
Adopt the reward-checkpoint approach recommended in the original report, adapted to PoX-5's accumulator model: instead of dividing the whole elapsed period's rewards by the current share total, require `calculate-rewards` to be invoked incrementally (e.g., every time total shares change, settle a partial reward-per-token snapshot up to that block) or restrict stake changes to only take effect at reward-cycle boundaries, so a staker's shares can only earn from the *next* full accrual window onward, never a window already substantially elapsed at stake time.

### Proof of Concept
Conceptual reproduction using the contract's own test model math:
1. Staker A stakes `X` uSTX at the start of a distribution window (`stake` call, cycle N).
2. Reward tokens (e.g., sBTC) accumulate in the contract over the window (`gross-accrued-rewards` grows via `get-new-rewards`).
3. Immediately before anyone calls `calculate-rewards`, Staker B stakes `9X` uSTX for cycle N, so `cycle-staked-ustx` becomes `10X` (per `get-total-shares-staked-for-cycle`, `pox-5.clar` line 2192).
4. `calculate-rewards` runs; `accrued-rewards-per-ustx` is computed as `stx-staker-rewards * PRECISION / (10X)` (`pox-5.clar` lines 2197-2201).
5. Both A and B call `get-earned`/`claim-rewards`; B (who staked seconds before the calculation) receives 9/10 of the entire window's rewards despite having contributed 0% of the time those rewards accrued, matching the reported 90/10 outcome in the BellumNursery PoC.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2161-2166)
```text
            (calculation-height (- (distribution-cycle-to-burn-height (current-distribution-cycle))
                u1
            ))
            (cur-reserve (var-get reserve-balance))
            (gross-accrued-rewards (get-new-rewards))
            (stx-cycle (burn-height-to-reward-cycle calculation-height))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2192-2201)
```text
                (cycle-staked-ustx (get-total-shares-staked-for-cycle stx-cycle none))
                (current-rewards-per-ustx (get-rewards-per-token-for-cycle stx-cycle none))
                (prev-accounted-rewards (var-get last-accounted-rewards-only))
                ;; If no STX is staked this cycle, the staker cut will be applied to the reserve.
                (no-stx-stakers (is-eq cycle-staked-ustx u0))
                (accrued-rewards-per-ustx (if no-stx-stakers
                    u0
                    (/ (* stx-staker-rewards PRECISION) cycle-staked-ustx)
                ))
                (cumulative-rewards-per-ustx (+ current-rewards-per-ustx accrued-rewards-per-ustx))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2375-2385)
```text
;; Pure math formula for computing rewards earned since the last snapshot
;;
;; `earned = (shares * (rpt - rptPaid)) / PRECISION + pending`
(define-read-only (compute-earned-rewards
        (shares uint)
        (rpt-current uint)
        (rpt-paid uint)
        (pending uint)
    )
    (+ pending (/ (* shares (- rpt-current rpt-paid)) PRECISION))
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2525-2544)
```text
;; Update all earned-but-unclaimed rewards for a signer, and update the snapshot
;; (signer-rewards-per-token-settled-for-cycle) for the signer.
;;
;; This MUST be called before any update to `signer-shares-staked-for-cycle`,
;; because changes to that state will effect rewards calculations.
(define-private (settle-rewards
        (signer principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (let (
            (shares (get-signer-shares-staked-for-cycle signer reward-cycle bond-index))
            (rewards-per-token (get-rewards-per-token-for-cycle reward-cycle bond-index))
            (earned (compute-earned-rewards
                shares
                rewards-per-token
                (get-signer-rewards-per-token-settled-for-cycle signer reward-cycle bond-index)
                (get-signer-unclaimed-rewards-for-cycle signer reward-cycle bond-index)
            ))
        )
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L91-102)
```typescript
function claimableRewards({
  rewards,
  shares,
  totalShares,
}: {
  rewards: bigint;
  shares: bigint;
  totalShares: bigint;
}) {
  const rewardsPerShare = (rewards * pox5.constants.PRECISION) / totalShares;
  return (shares * rewardsPerShare) / pox5.constants.PRECISION;
}
```
