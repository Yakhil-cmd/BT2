### Title
Bond rewards bypass the `RESERVE_RATIO` protocol-fee cut applied to STX-staker rewards - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
In `calculate-rewards`, the pool of newly-accrued sBTC rewards is split between signer "bonds" and plain STX stakers. Only the STX-staker remainder is charged the protocol `RESERVE_RATIO` cut; the bond-reward path receives its full `target-yield` before any reserve is taken.

### Finding Description
`calculate-rewards` computes `gross-accrued-rewards` and folds it through `calculate-bond-rewards` for each requested bond period [1](#0-0) . Each bond earns `min(target-yield, available-rewards)` directly out of the gross pool, with no fee deduction [2](#0-1) .

Only after all bonds are paid does the function take `remaining-rewards` (`available-rewards` left over) and apply the protocol reserve cut:
```
(reserve-cut (/ (* remaining-rewards RESERVE_RATIO) u10000))
(stx-staker-rewards (- remaining-rewards reserve-cut))
``` [3](#0-2) 

This means `RESERVE_RATIO` (the protocol's fee/reserve mechanism, analogous to `barFee`) is levied exclusively on the plain-STX-staking reward stream and never on the sBTC-collateralized bond stream. Bonds get their full targeted APY paid out of gross rewards untaxed, while STX stakers absorb the entire reserve cut on what remains. This is structurally identical to the referenced SushiTrident finding: two competing "pools" (here, bonds vs. plain STX staking) draw from the same reward source, but one path is exempt from the protocol fee that the other must pay, incentivizing rational actors to prefer the fee-exempt path and starving the protocol reserve that `reserve-balance` is meant to accumulate.

### Impact Explanation
The `reserve-balance` collected via `RESERVE_RATIO` is explicitly protocol reserve funds accumulated across every reward calculation [4](#0-3) . Because bond rewards are fully paid before this cut is applied, every unit of sBTC that is routed through a bond escapes the reserve levy entirely. Over the life of the protocol this permanently starves the reserve of fees it should have collected on that portion of rewards — a permanent loss to the protocol reserve, matching the High-severity category "theft or permanent freezing of reserve or fees." It does not touch locked STX/BTC principal or create unbacked minting, so it does not rise to Critical.

### Likelihood Explanation
This triggers on every ordinary `calculate-rewards` call whenever any `bond-periods` are supplied and bonds have an active `target-rate` — i.e., in the normal, expected operation of the bond program, not a rare edge case. No privileged role is required; `calculate-rewards` is callable by anyone [5](#0-4) , and the asymmetric fee treatment is baked into the reward-splitting order, so it fires deterministically on every cycle bonds participate in.

### Recommendation
Apply `RESERVE_RATIO` to `gross-accrued-rewards` before splitting between bonds and STX stakers, so both the bond-reward stream and the STX-staker stream contribute proportionally to the protocol reserve — mirroring the intended symmetry between reward paths, analogous to ensuring `barFeeTo` fees are charged uniformly across all pool types in the referenced report.

### Proof of Concept
1. Assume `RESERVE_RATIO` is non-zero (e.g., 10%, `u1000` in the `/u10000` basis-point scale used at `stackslib/src/chainstate/stacks/boot/pox-5.clar:2190`).
2. sBTC rewards of `R` accrue to the pool; a signer registers an active bond whose `target-yield` equals `R` (or any large share of it) — see `calculate-bond-rewards` at `stackslib/src/chainstate/stacks/boot/pox-5.clar:2263-2272`.
3. Call `calculate-rewards` with that bond period included. The fold pays the bond `earned = target-yield` out of gross `R` with zero deduction (`stackslib/src/chainstate/stacks/boot/pox-5.clar:2269-2272`).
4. `remaining-rewards` (what's left for STX stakers) is now small; `reserve-cut` is computed only on this remainder (`stackslib/src/chainstate/stacks/boot/pox-5.clar:2190`).
5. Compare: if the same `R` had instead been earned entirely by STX stakers (no bonds), the reserve would have collected `R * RESERVE_RATIO / 10000`. With bonds absorbing most of `R`, the reserve collects `(R - bond_earned) * RESERVE_RATIO / 10000`, a strictly smaller (potentially near-zero) amount — demonstrating the reserve fee is permanently and systematically under-collected whenever bonds are active, with no compensating mechanism anywhere else in the contract (confirmed by the absence of any other `RESERVE_RATIO`/reserve-cut reference in `pox-5.clar`).

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2158-2168)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2179-2191)
```text
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2207-2214)
```text
                (reserve-deposit (+ reserve-cut unallocated-staker-cut))
                (new-reserve-balance (+ cur-reserve reserve-deposit))
            )
            (var-set reserve-balance new-reserve-balance)
            (var-set last-reward-compute-height calculation-height)
            (var-set last-accounted-rewards-only
                (+ prev-accounted-rewards
                    (- gross-accrued-rewards reserve-deposit)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2263-2279)
```text
            (available-rewards (get available-rewards accumulator))
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
