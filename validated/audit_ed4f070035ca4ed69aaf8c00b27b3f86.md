### Title
Reward-accumulator truncation dust becomes permanently frozen, unclaimable sBTC in `pox-5.clar` - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`calculate-rewards` distributes each cycle's newly-received sBTC (`gross-accrued-rewards`) into three buckets: bond rewards, the reserve, and the STX-staker pool. Both the STX-staker pool and each bond pool use a Synthetix-style `rewards-per-token` accumulator computed with a `PRECISION`-scaled integer division that floors. Although the accumulator floors, the contract's book-keeping variable `last-accounted-rewards-only` is incremented by the *full, un-floored* amount handed to each pool. Because `get-new-rewards`/`get-rewards` only ever look at `current-balance - staked - reserve - last-accounted-rewards-only`, the small remainder lost to flooring is silently absorbed into "already accounted for" state and can never again be seen as new rewards, claimed by any staker/signer, or swept to the reserve. It permanently sits in the contract's sBTC balance as unrecoverable dust — the exact bug class described in the external Lido report ("Node Operator Rewards Unevenly Leaked"), reproduced here inside `pox-5`'s own reward-accumulator math rather than in an external token integration.

### Finding Description
`get-rewards`/`get-new-rewards` compute the amount of "new" sBTC available for distribution purely as a balance delta: [1](#0-0) 

`calculate-rewards` splits `gross-accrued-rewards` into bond rewards (via `calculate-bond-rewards`), a `reserve-cut`, and `stx-staker-rewards`, then updates `last-accounted-rewards-only` by `(gross-accrued-rewards - reserve-deposit)` — i.e. the *entire* remainder including the STX-staker and bond pools' full nominal share, not the amount that the accumulator math can actually distribute: [2](#0-1) 

The STX-staker accumulator increment itself floors:
```
(accrued-rewards-per-ustx (if no-stx-stakers u0
    (/ (* stx-staker-rewards PRECISION) cycle-staked-ustx)))
``` [3](#0-2) 

and the bond accumulator does the same:
```
(accrued-rewards-per-sat (if (is-eq total-sats u0) u0
    (/ (* earned PRECISION) total-sats)))
``` [4](#0-3) 

When a signer/staker later claims, `compute-earned-rewards` again floors: `earned = pending + (shares * (rpt-current - rpt-paid)) / PRECISION`: [5](#0-4) 

Because of this double flooring (once when computing `accrued-rewards-per-ustx`/`-per-sat`, and again when converting each staker's shares back from the accumulator), the sum of everything that is actually claimable from a given `stx-staker-rewards`/bond `earned` allotment is strictly `<=` the nominal amount credited into `last-accounted-rewards-only`. The difference — bounded by roughly one wei-equivalent of sBTC per active staker/signer per calculation, matching the "k stETH wei per period" bound described in the external report — is never assigned to any principal's unclaimed-rewards map, never added to the `reserve-balance`, and is permanently excluded from future `get-new-rewards()` computations because `last-accounted-rewards-only` has already "consumed" it. There is no sweep function analogous to `signer-manager.clar`'s `sweep-fee-refunds` for this residual in `pox-5.clar`. This dust accumulates release-over-release exactly like the Lido `NodeOperatorRegistry` bug, and unlike the resolved Lido design (where residuals go to the treasury), here it is simply lost inside the contract's own sBTC balance forever.

### Impact Explanation
This is a permanent freezing of reward-pool sBTC funds: value that was correctly received by `pox-5.clar` as staking/bonding rewards becomes stuck in the contract, uncredited to any staker/signer's unclaimed-rewards accounting and unreachable by the reserve or any admin sweep, for the lifetime of the contract. Per-operation the amount is small (bounded by the number of active reward-token holders per cycle, similar to the original report), but it compounds every `calculate-rewards` call across all cycles and bonds, permanently misallocating protocol value away from stakers/signers without any path to recovery.

### Likelihood Explanation
This triggers on essentially every normal, unprivileged call to `calculate-rewards` whenever `cycle-staked-ustx` (or a bond's `total-sats`) does not evenly divide `stx-staker-rewards * PRECISION` (or `earned * PRECISION`) — which is the common case for any real-world set of staked amounts. No malicious actor or special conditions are required; it happens automatically as part of routine reward computation.

### Recommendation
Track and reconcile flooring dust instead of folding the full nominal pool amount into `last-accounted-rewards-only`. Concretely: after computing `accrued-rewards-per-ustx`/`accrued-rewards-per-sat` via floor division, recompute the amount actually represented by the accumulator (`accrued-rewards-per-x * total-shares / PRECISION`), and only add that reconciled (already-floored) amount into `last-accounted-rewards-only`/reserve bookkeeping, redirecting the leftover truncation remainder explicitly to `reserve-balance` (mirroring the `unallocated-staker-cut` pattern already used for the no-stakers case). This keeps `get-new-rewards()` correctly picking up the truncation dust on the next call (or explicitly reserves it), eliminating the permanently-stuck sBTC.

### Proof of Concept
1. Signer stakes STX in `stx-only` pool with `cycle-staked-ustx` chosen such that `stx-staker-rewards * PRECISION` does not divide evenly by `cycle-staked-ustx` (trivial with realistic amounts, e.g. any prime-factor mismatch).
2. `deployer` transfers sBTC rewards to `pox-5`, then calls `calculate-rewards([])`. `accrued-rewards-per-ustx` is floored, e.g. leaving a remainder `r > 0` of sBTC.
3. `last-accounted-rewards-only` is incremented by the *full* `stx-staker-rewards` (not `stx-staker-rewards - r`), per `stackslib/src/chainstate/stacks/boot/pox-5.clar:2212-2215`.
4. Signer claims via `claim-rewards`; `compute-earned-rewards` floors again per share, so the total claimed by all signers over the cycle is `stx-staker-rewards - r` (or less, with more signers).
5. The residual `r` sBTC now permanently sits in the contract's sBTC balance: `get-rewards()` (balance − staked − reserve) no longer surfaces it because `last-accounted-rewards-only` already absorbed the full `stx-staker-rewards`, and no function in `pox-5.clar` exposes a path to reclaim or redistribute it. Repeated across cycles and bonds, this dust accumulates without bound and without recovery.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2135-2156)
```text
(define-read-only (get-rewards)
    (let (
            (cur-reserve (var-get reserve-balance))
            (total-staked-sbtc (get-total-sbtc-staked))
            (current-balance (unwrap-panic (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance current-contract
            )))
        )
        (- current-balance total-staked-sbtc cur-reserve)
    )
)

;; Returns the total amount of newly received sBTC rewards
;; since the last rewards computation
(define-read-only (get-new-rewards)
    (let (
            (last-accounted-rewards (var-get last-accounted-rewards-only))
            (rewards-balance (get-rewards))
        )
        (- rewards-balance last-accounted-rewards)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2189-2220)
```text
                (remaining-rewards (get available-rewards bond-distributions))
                (reserve-cut (/ (* remaining-rewards RESERVE_RATIO) u10000))
                (stx-staker-rewards (- remaining-rewards reserve-cut))
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
                ;; When no STX is staked, fold the staker cut into the reserve, otherwise zero.
                (unallocated-staker-cut (if no-stx-stakers
                    stx-staker-rewards
                    u0
                ))
                (reserve-deposit (+ reserve-cut unallocated-staker-cut))
                (new-reserve-balance (+ cur-reserve reserve-deposit))
            )
            (var-set reserve-balance new-reserve-balance)
            (var-set last-reward-compute-height calculation-height)
            (var-set last-accounted-rewards-only
                (+ prev-accounted-rewards
                    (- gross-accrued-rewards reserve-deposit)
                ))
            (map-set rewards-per-token-for-cycle {
                reward-cycle: stx-cycle,
                bond-index: none,
            }
                cumulative-rewards-per-ustx
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2264-2279)
```text
            ;; How much sBTC the bond is supposed to earn per calculation,
            ;; which is (totalSats * apy) / 50
            (target-yield (/ (/ (* total-sats (get target-rate bond)) u10000) u50))
            ;; If there is enough to cover the target yield, use that. Otherwise,
            ;; this bond gets the remaining rewards.
            (earned (if (>= available-rewards target-yield)
                target-yield
                available-rewards
            ))
            (stx-value-ratio (get stx-value-ratio bond))
            (current-rewards-per-token (get-rewards-per-token-for-cycle reward-cycle (some bond-index)))
            ;; Prevent divide-by-zero
            (accrued-rewards-per-sat (if (is-eq total-sats u0)
                u0
                (/ (* earned PRECISION) total-sats)
            ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2378-2385)
```text
(define-read-only (compute-earned-rewards
        (shares uint)
        (rpt-current uint)
        (rpt-paid uint)
        (pending uint)
    )
    (+ pending (/ (* shares (- rpt-current rpt-paid)) PRECISION))
)
```
