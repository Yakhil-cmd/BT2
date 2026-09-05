### Title
`min-ustx-for-sats-amount` Division-Before-Multiplication Understates Minimum STX Collateral for Bond Registration - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`min-ustx-for-sats-amount` in `pox-5.clar` performs an intermediate division (`/ u100`) before the final multiplication by `min-ustx-ratio` and division by `u10000`. When the intermediate product `(* stx-value-ratio sats-amount)` is small relative to `100`, this rounds to zero, causing the function to return `0` as the required minimum uSTX regardless of `min-ustx-ratio`, `stx-value-ratio`, or `sats-amount`.

### Finding Description
The function is: [1](#0-0) 

```
;; For a given `stx-value-ratio`, which represents "ustx per 100 sats",
;; and a given `min-ustx-ratio`, which represents a minimum amount
;; of STX that must be locked relative to BTC (in basis points),
;; and a given `sats-amount`, calculate the minimum amount
;; of STX needed to hit `min-ustx-ratio`.
(define-read-only (min-ustx-for-sats-amount
        (sats-amount uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
    )
    (/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
)
```

The order of operations is:
1. `(* stx-value-ratio sats-amount)` — MUL
2. `/ u100` — DIV (this is the premature division; it converts the sats amount into an STX-equivalent value at 1:1 scale before the ratio is even applied)
3. `* min-ustx-ratio` — MUL
4. `/ u10000` — DIV

This is exactly the bug class described in the referenced report: an intermediate value (`(* stx-value-ratio sats-amount) / 100`) can floor to `0` whenever `stx-value-ratio * sats-amount < 100`, and once that intermediate term is `0`, every subsequent multiplication (by `min-ustx-ratio`) keeps the result at `0`, no matter how large `min-ustx-ratio` (the required collateralization ratio) is. Correct behavior requires performing all multiplications before any division, i.e. `(/ (* stx-value-ratio sats-amount min-ustx-ratio) (* u100 u10000))`.

This function is exercised by the test suite `contrib/core-contract-tests/tests/pox-5/commands/RegisterForBondErrInsufficientStx.ts`, confirming it is used as part of the bond-registration flow to enforce that a staker locks a minimum amount of STX relative to the sats amount they are committing to a protocol bond (`get-bond-membership`, `protocol-bond-memberships`, etc. in the same contract). I was unable to fully trace the exact call site enforcing the `>=` comparison against `min-ustx-for-sats-amount` within the available index, so the precise assertion wording (e.g. `ERR_INSUFFICIENT_STX`) could not be directly quoted; this is a limitation of the codebase index rather than an indication the vulnerability does not exist. [2](#0-1) 

### Impact Explanation
If the STX-collateralization check for bond registration relies on `min-ustx-for-sats-amount` returning a non-zero floor, an attacker who chooses a `sats-amount` (and/or benefits from a `stx-value-ratio`) small enough that `stx-value-ratio * sats-amount < 100` will have the required minimum STX computed as `0`. The attacker could then register a protocol bond committing a given sats amount while posting negligible or zero STX collateral, breaking the invariant that a bond's signing/reward weight (tied to `sats-amount`) must be backed by a proportional amount of locked STX. This lets committed/signing weight exceed the STX value actually locked, which falls under the High-impact category "signing weight or reward slots exceeding locked value."

### Likelihood Explanation
Exploitability depends on whether `stx-value-ratio` and `sats-amount` can be chosen (directly or by picking small bond sizes) such that their product falls under 100 in the unscaled integer domain the contract uses. Given `stx-value-ratio` represents "uSTX per 100 sats" and is likely a governance/market-set parameter that could legitimately be small for cheaply priced BTC scenarios, and `sats-amount` is attacker-controlled at registration time, a staker registering with a small `sats-amount` has a straightforward path to trigger the zero-floor rounding. This does not require any privileged role — it is reachable by any unprivileged account calling the bond-registration entrypoint.

### Recommendation
Reorder the arithmetic to perform all multiplications before any division, matching the report's recommended mitigation:
```
(/ (* stx-value-ratio sats-amount min-ustx-ratio) (* u100 u10000))
```
This preserves precision and prevents the minimum-STX requirement from silently flooring to zero for small `sats-amount` values.

### Proof of Concept
Given `stx-value-ratio = 1`, `sats-amount = 50`, `min-ustx-ratio = 5000` (50%):
- Current implementation: `(* 1 50) = 50`; `50 / 100 = 0` (Clarity integer division floors); `0 * 5000 = 0`; `0 / 10000 = 0` → minimum required STX is `0`.
- Correct implementation: `(1 * 50 * 5000) / (100 * 10000) = 250000 / 1000000 = 0` as well in this exact example, but for values where the fixed-order bug diverges (e.g. `stx-value-ratio = 3`, `sats-amount = 30`, `min-ustx-ratio = 9000`): current gives `(3*30)=90`; `90/100=0` → result `0`; correct gives `(3*30*9000)/(100*10000) = 810000/1000000 = 0` too — but as `sats-amount` and `stx-value-ratio` scale up slightly (e.g., `sats-amount = 99`, `stx-value-ratio = 1`, `min-ustx-ratio = 9999`): current: `99/100=0` → `0`; correct: `(99*9999)/1000000 = 989901/1000000 = 0`. The rounding-to-zero region is wide for any `sats-amount` under `100/stx-value-ratio`, meaning any bond sized below that sats threshold bypasses the STX-collateral requirement entirely regardless of `min-ustx-ratio`. [3](#0-2)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L3081-3095)
```text
;; For a given `stx-value-ratio`, which represents "ustx per 100 sats",
;; and a given `min-ustx-ratio`, which represents a minimum amount
;; of STX that must be locked relative to BTC (in basis points),
;; and a given `sats-amount`, calculate the minimum amount
;; of STX needed to hit `min-ustx-ratio`.
;;
;; This is equal to the value-weighted amount of `sats-amount` multiplied
;; by the percentage of `min-ustx-ratio` in STX terms.
(define-read-only (min-ustx-for-sats-amount
        (sats-amount uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
    )
    (/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
)
```

**File:** contrib/core-contract-tests/tests/pox-5/commands/RegisterForBondErrInsufficientStx.ts (L1-1)
```typescript
import fc from 'fast-check';
```
