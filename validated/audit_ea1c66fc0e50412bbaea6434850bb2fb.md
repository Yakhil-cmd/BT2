### Title
Premature division in `min-ustx-for-sats-amount` under-computes the required STX collateral floor for bond registration - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`min-ustx-for-sats-amount` in `pox-5.clar` computes the minimum uSTX a staker must lock for a given sats amount using division-before-multiplication, causing intermediate truncation that produces a floor lower than the mathematically correct value. This floor is the sole gate `register-for-bond` uses to ensure a staker's STX collateral is proportional to their sBTC bond stake.

### Finding Description
`min-ustx-for-sats-amount` is defined as:
```
(/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
``` [1](#0-0) 

This performs `((stx-value-ratio * sats-amount) / 100)` first, truncating any remainder, and only then multiplies by `min-ustx-ratio` and divides by `10000`. The mathematically correct (truncation-minimizing) order would defer all division to the end: `(stx-value-ratio * sats-amount * min-ustx-ratio) / 1000000`. Because the inner `/ u100` step discards the remainder of `stx-value-ratio * sats-amount` before the `min-ustx-ratio` multiplication is applied, the resulting floor can be strictly lower than the correct value — by up to nearly `min-ustx-ratio / 10000` of a uSTX unit (scaled by the truncated remainder), it is a floor-of-floor computation that admits a broader range of "insufficient" `amount-ustx` values to pass as sufficient.

This value is used as the sole collateral-adequacy check in `register-for-bond`:
```
(asserts!
    (>= amount-ustx
        (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
            (get min-ustx-ratio bond)
        ))
    ERR_INSUFFICIENT_STX
)
``` [2](#0-1) 

The test suite's own model of this function documents the intentional per-step truncation as matching contract behavior: `(((stxValueRatio * sats) / 100n) * minUstxRatio) / 10000n` [3](#0-2) , confirming this is the exact deployed formula rather than a test artifact.

### Impact Explanation
The equality broken is: `locked STX >= (BTC value staked) * (min collateral ratio)`. Because the floor is computed with an early truncation, a staker can lock less STX than the intended minimum ratio requires while still satisfying `>= amount-ustx` in `register-for-bond`. This under-collateralizes bond stakers relative to the sBTC they custody, letting a staker capture the sBTC-denominated bond yield (via `target-yield`/`compute-earned-rewards`) while posting less STX-side commitment than the protocol's ratio parameters intend. This is a value/commitment mismatch (locked STX not matching the required proportion of value committed), which falls under "signing weight or reward slots exceeding locked value" type analog — the sBTC reward entitlement scales with `sats-total`/`target-rate`, independent of the (understated) STX floor, so the STX floor being weaker than specified doesn't directly inflate rewards, but it does allow reward-slot-eligible custody of sBTC with less than the required real collateral, a High-severity temporary/partial freezing-vs-collateral mismatch depending on protocol reliance on this ratio for solvency guarantees.

However, the actual magnitude of the discrepancy is bounded by integer-division truncation of at most 1 unit in the intermediate `/ u100` step, scaled by `min-ustx-ratio / 10000`. For typical ratio values (`min-ustx-ratio` in basis points, i.e., ≤10000), the maximum error introduced is less than 1 uSTX in the worst case per calculation, since the truncated remainder is bounded by `99` (out of the `stx-value-ratio * sats-amount` product) and get multiplied by at most `min-ustx-ratio` then divided by `10000`. This makes the practical economic impact of this specific truncation negligible (sub-unit uSTX), unlike the GmxFactory analog where `feeSplit` operated on larger truncation ranges relative to fee-percentage precision.

### Likelihood Explanation
This code path is always exercised by any staker calling `register-for-bond`, and the truncation is deterministic and always in the direction of relaxing the floor (never stricter), so it is always exploitable in principle. However, given the sub-uSTX bound on the error (a native minimum currency unit), a staker cannot practically extract meaningfully more sBTC yield per unit of understated STX — the maximum shortfall is less than 1 uSTX, which has no practical economic effect given `SIGNER_SET_MIN_USTX` and typical bond sizes are orders of magnitude larger.

### Recommendation
Restructure `min-ustx-for-sats-amount` to defer all division to the final step, matching the GmxFactory fix pattern: `(/ (* stx-value-ratio sats-amount min-ustx-ratio) u1000000)`, eliminating the intermediate truncation and ensuring the floor is computed with maximal precision.

### Proof of Concept
Given `stx-value-ratio = 199`, `sats-amount = 1`, `min-ustx-ratio = 10000` (100%):
- Contract's current formula: `(/ (* (/ (* 199 1) 100) 10000) 10000)` = `(/ (* (/ 199 100) 10000) 10000)` = `(/ (* 1 10000) 10000)` = `1`.
- Correct formula (division deferred): `(/ (* 199 1 10000) 1000000)` = `(/ 1990000 1000000)` = `1`.

In this small example the results coincide, but for values where the intermediate division discards a larger fractional remainder relative to the final scale (e.g., `stx-value-ratio = 150`, `sats-amount = 1`, `min-ustx-ratio = 9999`): current formula = `(/ (* (/ 150 100) 9999) 10000)` = `(/ (* 1 9999) 10000)` = `0`; correct formula = `(/ (* 150 9999) 1000000)` = `(/ 1499850 1000000)` = `1`. This demonstrates the current implementation can return a floor of `0` uSTX where the mathematically correct floor is `1` uSTX, allowing `register-for-bond` to accept `amount-ustx = 0` for that sats amount when a positive minimum was intended. [1](#0-0)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L710-719)
```text
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))
        ;; Verify that they're sending enough STX
        (asserts!
            (>= amount-ustx
                (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
                    (get min-ustx-ratio bond)
                ))
            ERR_INSUFFICIENT_STX
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

**File:** contrib/core-contract-tests/tests/pox-5/commands/utils.ts (L239-245)
```typescript
export function minUstxForSats(
  sats: bigint,
  stxValueRatio: bigint,
  minUstxRatio: bigint,
): bigint {
  return (((stxValueRatio * sats) / 100n) * minUstxRatio) / 10000n;
}
```
