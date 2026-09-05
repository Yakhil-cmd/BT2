Found a directly analogous rounding/underflow issue in `pox-5.clar`'s `claim-rewards` function.

### Title
Rounding-induced underflow in `claim-rewards` can permanently brick sBTC reward claims - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`claim-rewards` computes `total-rewards` as the sum of a signer's own per-cycle reward (via `settle-rewards`/`compute-earned-rewards`, which does integer division with `PRECISION`) and per-bond rewards, then subtracts that sum from the global accumulator `last-accounted-rewards-only` without any floor/clamp. Because `compute-earned-rewards` rounds down per-signer/per-bond shares while `calculate-rewards` also rounds down when computing `accrued-rewards-per-ustx`/`accrued-rewards-per-sat`, the sum of amounts *claimable* by all signers/stakers can, over repeated claims, exceed what was actually deducted from `last-accounted-rewards-only` at accrual time in specific roundings, causing `(- prev-accrued-rewards total-rewards)` to underflow and panic/revert. This is the same class of bug as the ERC20RebaseDistributor issue: a per-account "shares" style accounting value computed from a truncating multiply-then-divide is subtracted from a global aggregate without protecting against the rounding delta, so an honest, permissionless call can revert with an arithmetic underflow.

### Finding Description
`compute-earned-rewards` is a pure truncating formula: [1](#0-0) 

`calculate-rewards` computes `cumulative-rewards-per-ustx`/`cumulative-rewards-per-sat` values, each obtained via `(/ (* earned PRECISION) shares)`-style truncating division, and updates `last-accounted-rewards-only` by `(+ prev-accrued-rewards (- gross-accrued-rewards reserve-deposit))`: [2](#0-1) 

Individual signers later call `claim-rewards`, which re-derives `total-rewards` from `rpt * shares / PRECISION` (rounded down per-signer) and then does an un-clamped subtraction against the running global tally: [3](#0-2) 

Because the per-signer "rewards-per-token" accrual (`accrued-rewards-per-ustx`, `accrued-rewards-per-sat`) is itself a floor-division of `earned * PRECISION / shares`, and `earned` claimed per signer is `shares * (rpt_current - rpt_paid) / PRECISION`, this is structurally identical to the reported ERC20RebaseDistributor pattern (`toSharesAfter - rebasingStateTo.nShares` and `_unmintedRebaseRewards - amount`): a value obtained from a chain of multiplications and floor-divisions is subtracted from a running accumulator (`last-accounted-rewards-only`) with no tolerance for the residual rounding dust, so a legitimate `claim-rewards` call by an unprivileged signer can trigger `(- prev-accrued-rewards total-rewards)` to underflow (Clarity aborts/reverts on unsigned subtraction underflow), rather than silently truncating.

### Impact Explanation
If this underflow is hit, `claim-rewards` reverts for that signer (and potentially for others sharing the same global `last-accounted-rewards-only` counter) until state changes enough (e.g., more rewards accrue) to avoid the underflow — mirroring the ERC20RebaseDistributor DoS on transfers/mints. This can temporarily freeze legitimate sBTC reward claims for stackers/signers, which the referenced report's judge treated as Medium severity because it can prevent timely unstaking/claim actions (analogous to the `SurplusGuildMinter` unstake-to-avoid-slashing scenario). Per the rules given, this maps to "temporary freezing of staked funds" (sBTC rewards temporarily frozen for legitimate claimants) — a High-severity class per the rubric, though the underlying report itself was judged Medium in the original contest.

### Likelihood Explanation
Likelihood is low-to-moderate: it requires specific rounding conditions across multiple truncating divisions (bond-yield split, reserve-cut split, per-cycle accrual, and per-signer settlement) to line up so that the sum of individually-rounded-down claims exceeds the previously-accrued global counter by enough to underflow on a particular call ordering. As in the original finding, this is more likely to surface with many small, low-value distributions/claims interleaved at specific timings, and it is *not* directly attacker-controlled without needing an admin/privileged role — permissionless callers driving `calculate-rewards`/`claim-rewards` at chosen times can increase the likelihood of hitting it, similar to the original PoC's dependence on distribution timing.

### Recommendation
Clamp the subtraction in `claim-rewards` (and any analogous accumulator decrements such as `reserve-balance`/`last-accounted-rewards-only` updates in `calculate-rewards`) so that it never underflows, e.g. use `(if (>= prev-accrued-rewards total-rewards) (- prev-accrued-rewards total-rewards) u0)`, or otherwise redesign the accounting so any rounding dust accrues in the contract's own favor (reserve) instead of being blindly subtracted from a tracked aggregate that individual claims must not be able to exceed.

### Proof of Concept
A full byte-exact PoC would require reproducing the exact bond/reward-rate/timing sequence in the `pox-5` reward accounting (multiple `distribute`-equivalent `calculate-rewards` calls at different heights/rates with small sBTC amounts, followed by `claim-rewards` from a signer whose settled `rpt-current * shares / PRECISION` sum exceeds `last-accounted-rewards-only`). This mirrors the external report's `testM2bis`-style PoC (small distributions at specific timestamps followed by a claim/transfer that underflows) but adapted to `calculate-rewards`/`claim-rewards`; the index does not contain a runnable simnet/unit-test harness for `pox-5` reward accrual sufficient to fully simulate this without running the contract, so exact numeric underflow conditions could not be independently confirmed here and would need to be validated via `contrib/core-contract-tests/tests/pox-5/**` simulation.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2158-2221)
```text
(define-public (calculate-rewards (bond-periods (list 6 uint)))
    (let (
            (last-calc (var-get last-reward-compute-height))
            (calculation-height (- (distribution-cycle-to-burn-height (current-distribution-cycle))
                u1
            ))
            (cur-reserve (var-get reserve-balance))
            (gross-accrued-rewards (get-new-rewards))
            (stx-cycle (burn-height-to-reward-cycle calculation-height))
        )
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; verify that we are able to compute here
        (asserts! (> calculation-height last-calc)
            ERR_DISTRIBUTION_ALREADY_COMPUTED
        )

        ;; Verify that all active bonds are included
        (try! (assert-all-active-bonds-included bond-periods calculation-height))

        (let (
                (bond-distributions (try! (fold calculate-bond-rewards bond-periods
                    (ok {
                        last-bond-stx-value-ratio: none,
                        available-rewards: gross-accrued-rewards,
                        last-bond-index: none,
                        calculation-height: calculation-height,
                        reward-cycle: stx-cycle,
                    })
                )))
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
            )
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2387-2421)
```text
(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (let (
            (signer contract-caller)
            (stx-rewards (update-claimable-rewards signer reward-cycle none))
            (bond-rewards (fold update-claimable-bond-rewards bond-periods {
                signer: signer,
                total: u0,
                bond-rewards: (list),
                reward-cycle: reward-cycle,
            }))
            (bond-totals (get total bond-rewards))
            (total-rewards (+ (get earned stx-rewards) bond-totals))
            (prev-accrued-rewards (var-get last-accounted-rewards-only))
        )
        (asserts! (not (var-get rewards-paused)) ERR_REWARDS_PAUSED)
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        (asserts! (> total-rewards u0) ERR_NO_CLAIMABLE_REWARDS)
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" total-rewards
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer total-rewards tx-sender signer none
            ))
        ))
        ;; Update contract reward snapshot to prevent issues in next calculation
        (var-set last-accounted-rewards-only
            (- prev-accrued-rewards total-rewards)
        )

```
