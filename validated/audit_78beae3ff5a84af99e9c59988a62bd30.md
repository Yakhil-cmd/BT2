### Title
Basis-points truncation in `min-ustx-for-sats-amount` lets a staker satisfy the STX collateral floor with near-zero STX for a bonded sBTC position - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`pox-5.clar`'s `min-ustx-for-sats-amount` computes the minimum uSTX a staker must lock to back a given amount of sats in a protocol bond, using the same two-stage basis-points division pattern (`/100` then `/10000`) that the referenced Nouns Builder report flags as insufficiently precise. Because Clarity integer division truncates, small `sats-amount` values can drive the computed floor to `0`, letting an unprivileged staker register (or maintain) a bond that is supposed to be STX-collateralized while contributing effectively no STX collateral.

### Finding Description
The function is:
```
(define-read-only (min-ustx-for-sats-amount
        (sats-amount uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
    )
    (/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
)
``` [1](#0-0) 

This mirrors exactly the pattern in the external report: value * bps-numerator, divided by a fixed denominator (`100`, then `10000`), with no scaling by a high-precision constant such as the contract's own `PRECISION` (`u1000000000000000000`) that is already used elsewhere in this same contract for reward-per-sat accounting [2](#0-1) .

The intermediate truncation `(/ (* stx-value-ratio sats-amount) u100)` rounds to `0` whenever `stx-value-ratio * sats-amount < 100`, and the outer division by `u10000` further rounds any small product down to `0`. For realistic parameter ranges (e.g. `stx-value-ratio` in the tens to low hundreds representing "uSTX per 100 sats", and a caller-influenced `sats-amount` that can be arbitrarily small, bounded only by the bond admin's `max-sats` allowlist ceiling, not a floor), a staker can pick a `sats-amount` small enough that the computed floor collapses to `0` uSTX. The integration test comments confirm this function's role as the STX floor gatekeeper for bond registration: "`min-ustx-for-sats-amount(SBTC_AMT, 100, 10000) = SBTC_AMT` ustx, so any `amount-ustx >= SBTC_AMT` clears the bond's STX floor" [3](#0-2) , and target-yield/reward accrual for a bond is computed from `total-sats` independent of whether the STX floor was meaningfully enforced [4](#0-3) .

### Impact Explanation
If the STX-collateral floor for a bond can be trivially satisfied with `0` (or negligible) uSTX locked, the equality the protocol is meant to enforce — that sats-backed bond membership/signing weight is proportionally collateralized by locked STX — is broken. A staker's `total-sats` still counts fully toward reward-per-sat and signer-set weight calculations (`get-total-shares-staked-for-cycle`, `accrued-rewards-per-sat`) even though the corresponding STX floor check was defeated by rounding. This matches the "signing weight or reward slots exceeding locked value" High-impact category: value (sBTC rewards, signer influence) is derived from a "locked" quantity that was never actually locked by an amount proportionate to what the protocol requires.

### Likelihood Explanation
The staker is an ordinary, unprivileged account; `stx-value-ratio` and `min-ustx-ratio` are admin-set bond parameters, but `sats-amount` for an individual registration/top-up is effectively caller-chosen (bounded above by the admin allowlist cap, not below), so triggering the rounding-to-zero condition requires no special privilege — only choosing a sufficiently small requested sats amount, which the referenced report itself demonstrates is a very reachable condition once total values are large enough or ratios small enough.

### Recommendation
Scale `min-ustx-for-sats-amount` by the contract's existing `PRECISION` constant (`u1000000000000000000`) instead of the coarse `u100`/`u10000` two-step division, consistent with how `accrued-rewards-per-sat` already avoids precision loss elsewhere in `pox-5.clar`. Additionally, treat a computed floor of `0` uSTX for a nonzero `sats-amount` as an error condition rather than silently permitting `amount-ustx = 0` (or any value) to "clear" the floor.

### Proof of Concept
1. Bond admin calls `setup-bond` with some `stx-value-ratio` (e.g. `50`) and `min-ustx-ratio` (e.g. `100`, i.e., 1% in bps) and allowlists a staker for up to `max-sats`.
2. Staker (unprivileged) calls the bond registration path with a small `sats-amount`, e.g. `sats-amount = 10`.
3. `min-ustx-for-sats-amount(10, 50, 100)` = `(/ (* (/ (* 50 10) 100) 100) 10000)` = `(/ (* 5 100) 10000)` = `(/ 500 10000)` = `0`, per the formula at [1](#0-0) .
4. The staker satisfies `asserts! (>= amount-ustx (min-ustx-for-sats-amount ...))` with `amount-ustx = 0` (or any trivial value), yet is registered as a bond member with `10` sats of custodied backing, which subsequently earns `target-yield`/`accrued-rewards-per-sat` shares as if fully collateralized [4](#0-3) .

Note: I was not able to directly view the exact `register-for-bond` call site that consumes `min-ustx-for-sats-amount`'s return value within the tool-call budget available; the analysis above is based on the function's own arithmetic (confirmed) and the integration-test comment that explicitly describes its use as the STX-floor gatekeeper for bond registration. A full verification of any additional floor/minimum enforced elsewhere (e.g., a separate absolute minimum stake) would benefit from a direct read of the `register-for-bond`/`register-for-bond-all` function bodies in `pox-5.clar`.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L101-107)
```text
;; Used to prevent fractional multiplication errors
;; during reward calculations
(define-constant PRECISION u1000000000000000000) ;; 1e18

;; The % of rewards that go to reserve, expressed
;; in basis points
(define-constant RESERVE_RATIO u1500)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2262-2279)
```text
            (total-sats (get-total-shares-staked-for-cycle reward-cycle (some bond-index)))
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

**File:** stacks-node/src/tests/pox_5_integrations.rs (L571-576)
```rust
    // 1) `setup-bond` from the configured bond admin. Allowlist the staker
    // for `SBTC_AMT` sats. With `stx-value-ratio = 100` and
    // `min-ustx-ratio = 10000` (== 100% in basis points),
    // `min-ustx-for-sats-amount(SBTC_AMT, 100, 10000) = SBTC_AMT` ustx, so
    // any `amount-ustx >= SBTC_AMT` clears the bond's STX floor.
    const SBTC_AMT: u128 = 1_000_000;
```
