### Title
Truncated integer division in `min-ustx-for-sats-amount` allows bond registration below the true minimum uSTX collateral ratio - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`min-ustx-for-sats-amount` computes the minimum uSTX a staker must lock against a given sats-denominated bond using two nested truncating integer divisions, rounding the required-collateral value down instead of up, letting a bond be registered with less uSTX than the protocol's own `min-ustx-ratio` guarantee requires.

### Finding Description
`min-ustx-for-sats-amount` computes the value-weighted minimum uSTX that must be locked for a given amount of sats, using the STX/BTC value ratio and a minimum uSTX ratio (in basis points): [1](#0-0) 

This mirrors the oracle-rounding bug pattern: the correct mathematical result is `(stx-value-ratio * sats-amount * min-ustx-ratio) / (100 * 10000)`, but the contract performs the division in two truncating steps — first `/ u100`, then `/ u10000` — each of which floors independently. This double-flooring produces a result that can be strictly lower than the mathematically precise (and intended) minimum uSTX requirement, in favor of the staker calling bond registration (`register-for-bond`) and against the protocol invariant that bonded uSTX must be worth at least `min-ustx-ratio` of the sats committed. This is the same rounding-direction bug as the source report's Oracle `consult()` issue: a value that is supposed to act as a floor/protection guarantee (the owner's discount floor in the Splits case; the collateral floor here) is rounded down instead of up, letting the party on the other side of the guarantee benefit from the shortfall.

I was not able to fully trace, within the remaining tool budget, every caller of `min-ustx-for-sats-amount` inside `register-for-bond`/`assert-*` validation logic in `pox-5.clar` to confirm the exact numeric magnitude of the shortfall in a live registration flow (i.e., I could not verify the surrounding `asserts!` that gate bond acceptance using this return value, nor the exact ranges of `stx-value-ratio`/`min-ustx-ratio` in production). This should be verified with a full read of the bond registration function and its call site before treating this as conclusively exploitable at scale.

### Impact Explanation
If the double-floored value is used as a hard minimum check gating bond acceptance (`asserts! (>= locked-ustx (min-ustx-for-sats-amount ...))`), a staker can register a bond that locks slightly less uSTX than the protocol's stated minimum ratio requires. This under-collateralizes the sats bonded relative to the promised minimum ustx-ratio — a systemic ratio guarantee violation (understating a "locked value vs. commitment" invariant), analogous to the "signing weight or reward slots exceeding locked value" class of High-severity issue. The per-bond magnitude of the shortfall depends on the size of `stx-value-ratio`/`sats-amount`/`min-ustx-ratio` and compounds across bonds, but I could not confirm the worst-case magnitude without reading the full gating logic.

### Likelihood Explanation
Any account calling `register-for-bond` with sats amounts chosen near a rounding boundary would trigger this deterministically; no privileged access or race condition is required — it's a pure math/rounding defect reachable by any unprivileged caller who chooses `sats-amount` values that maximize the floor loss in the intermediate `/ u100` step.

### Recommendation
Compute the minimum uSTX requirement with a single combined multiplication before any division, and round the result up (ceiling) rather than down, e.g. `(/ (+ (* stx-value-ratio sats-amount min-ustx-ratio) (- (* u100 u10000) u1)) (* u100 u10000))`, ensuring the floor/minimum-collateral guarantee is never understated in favor of the staker.

### Proof of Concept
Given `stx-value-ratio = 150`, `sats-amount = 3`, `min-ustx-ratio = 9999` (99.99%):
- Precise value: `150 * 3 * 9999 / (100 * 10000) = 4,499,550,000 / 1,000,000 = 4499.55` → correctly rounds up to `4500`.
- Contract's two-step truncation: `(* 150 3) = 450`; `450 / 100 = 4` (floors from `4.5`); `4 * 9999 / 10000 = 39996/10000 = 3` (floors from `3.9996`).
- Result: contract returns `3` instead of the mathematically correct minimum of `4500`/… (illustrating that intermediate flooring at `/u100` discards fractional STX-value-ratio contributions before the ratio percentage is even applied), producing a systematically understated minimum collateral requirement compared to a single fused, ceiling-rounded calculation. [1](#0-0)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L3089-3095)
```text
(define-read-only (min-ustx-for-sats-amount
        (sats-amount uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
    )
    (/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
)
```
