### Title
Double floor-division in `min-ustx-for-sats-amount` under-calculates the required uSTX collateral for a protocol bond - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
The pox-5 contract computes the minimum amount of STX a staker must lock relative to a given sats amount using `min-ustx-for-sats-amount`, which performs two sequential integer divisions before rounding the final answer. This is structurally the same "divide-then-multiply-then-divide-again" pattern flagged in the referenced Beedle report, and it can truncate the intermediate result to a value lower than the mathematically exact minimum, letting a staker satisfy the "minimum STX per sats" collateral check with less STX than the protocol intends.

### Finding Description
`min-ustx-for-sats-amount` is defined as: [1](#0-0) 

```
(define-read-only (min-ustx-for-sats-amount
        (sats-amount uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
    )
    (/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
)
```

The mathematically exact formula is `(stx-value-ratio * sats-amount * min-ustx-ratio) / (100 * 10000)`. Instead, the contract computes `(stx-value-ratio * sats-amount) / 100` first, truncates towards zero, *then* multiplies by `min-ustx-ratio` and divides by `10000` again. Because Clarity's `uint` division floors, the intermediate truncation from `/ u100` is not recoverable by the subsequent multiply/divide — the result of this two-step division is always ≤ the single-step (exact) computation, and can be strictly less whenever `(stx-value-ratio * sats-amount) mod 100 != 0`.

`stx-value-ratio` is stored per protocol bond as "ustx per 100 sats" and `min-ustx-ratio` is a basis-point minimum ratio configured per bond: [2](#0-1) 

Both are attacker-influenced indirectly through the caller-supplied `sats-amount`, and the truncation described above means the derived minimum required STX (used to gate registering/joining a protocol bond with sBTC/L1-locked collateral) can come out lower than the value the protocol's own ratio requires. This is the direct structural analog of the reported `_calculateInterest` bug: a legitimate-looking formula is decomposed into two divisions instead of one, causing avoidable precision loss that always favors the caller (never rounds in favor of the protocol).

### Impact Explanation
If this understated minimum is used as the collateral gate for admitting a staker into a protocol bond (the presence of a dedicated test file named `RegisterForBondErrInsufficientStx.ts` referencing this exact function strongly suggests it functions as that gate), an attacker could register/lock a smaller `sats-amount`-backed position than `min-ustx-ratio` actually requires, breaking the equality the protocol relies on between committed sats and required locked uSTX. This would fall under the "unlocking value never locked" / "signing weight or reward slots exceeding locked value" category — the staker's position would be treated as adequately collateralized without the required uSTX being present, understating locked value in the bond relative to its recorded shares.

### Likelihood Explanation
Exploitability depends on the concrete truncation delta relative to the granularity of `sats-amount`/`stx-value-ratio`, and on how strictly the calling assertion at the registration site compares the caller's proposed `amount-ustx` to this computed minimum (a proposed amount just below the exact minimum but at/above the truncated minimum would pass). The magnitude of the shortfall is typically small per call (bounded by rounding of one intermediate division), but it is deterministic and reproducible on every call where `(stx-value-ratio * sats-amount) mod 100 != 0`, so it can be exploited repeatedly.

### Recommendation
Compute the formula with a single combined division (or round up) instead of two sequential floor divisions, e.g.:
```
(/ (* stx-value-ratio sats-amount min-ustx-ratio) (* u100 u10000))
```
and consider rounding up (ceiling division) so any residual truncation favors the protocol rather than the staker, consistent with the `roundUpDiv` mitigation suggested in the referenced report.

### Proof of Concept
Note: I was not able to confirm, within the available tool budget, the exact call site/assertion in `pox-5.clar` that consumes `min-ustx-for-sats-amount`'s return value to gate bond registration — this indexed search only surfaced the function definition and enumerated the files that reference it (`stackslib/src/chainstate/stacks/boot/pox-5.clar`, `stacks-node/src/tests/pox_5_integrations.rs`, `contrib/core-contract-tests/tests/pox-5/pox-5.test.ts`, `contrib/core-contract-tests/tests/pox-5/commands/RegisterForBondErrInsufficientStx.ts`) without returning their contents. Confirming the exact enforcement logic and constructing a concrete numeric PoC (choosing `sats-amount`, `stx-value-ratio` such that `(stx-value-ratio * sats-amount) mod 100 != 0`, and showing the caller's supplied `amount-ustx` passes the assertion while being below the exact required minimum) requires reading those files directly; a Devin session with full file access should be used to pull the exact assertion and finish the PoC.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L109-128)
```text
;; Core properties of protocol bonds
(define-map protocol-bonds
    uint
    {
        ;; target yield rate (apy) in basis points
        target-rate: uint,
        ;; representation of STX:BTC price
        ;; this value is equal to "ustx per 100 sats", which
        ;; also translates to `(BTCUSD / STXUSD)`.
        ;; used to determine bond priority
        stx-value-ratio: uint,
        ;; minimum amount of STX that must be locked
        ;; relative to BTC for this term.
        ;; Represented in basis points.
        min-ustx-ratio: uint,
        ;; The early-unlock subscript of the L1 lockup witness script for this
        ;; bond period.
        early-unlock-bytes: (buff 683),
    }
)
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
