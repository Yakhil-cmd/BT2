## Finding: `min-ustx-for-sats-amount` truncates to zero for small sats amounts, letting a staker register for an sBTC bond with **zero** STX collateral

### Title
`min-ustx-for-sats-amount` double-truncation lets stakers bypass the STX collateral floor for sBTC bonds - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`pox-5.clar`'s `min-ustx-for-sats-amount` computes the minimum STX that must be locked to back a given amount of staked sBTC, but performs **two sequential integer divisions**, causing the result to round down to `0` for reasonable, attacker-controlled inputs. Since `register-for-bond` only requires `amount-ustx >= (min-ustx-for-sats-amount ...)`, a staker can supply `amount-ustx = u0` and still pass the check, joining a protocol bond and accruing reward share weight backed by sBTC with **no slashable STX collateral** locked at all.

### Finding Description
The floor function is: [1](#0-0) 

```
(define-read-only (min-ustx-for-sats-amount
        (sats-amount uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
    )
    (/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
)
```

This performs `(/ (* stx-value-ratio sats-amount) u100)` first — truncating toward zero — and then multiplies that truncated intermediate value by `min-ustx-ratio` and divides by `u10000` again. Whenever `stx-value-ratio * sats-amount < 100`, the **inner** division already yields `0`, and the entire expression collapses to `0` regardless of `min-ustx-ratio`. For example, with `stx-value-ratio = 10` (a value used in the repo's own tests, e.g. `contrib/core-contract-tests/tests/pox-5/pox-5.test.ts:4222`), any `sats-amount <= 9` produces a minimum STX floor of `u0`.

`register-for-bond` gates the STX lock against exactly this floor (confirmed by the test comment describing the check as "the first `asserts!` after the prepare-phase guard"): [2](#0-1) 

Because the check is `(>= amount-ustx (min-ustx-for-sats-amount ...))`, an `amount-ustx` of `u0` trivially satisfies `(>= u0 u0)` when the floor truncates to zero. The staker can then supply a small (dust-level) sBTC amount via the `btcLockup`/sBTC transfer path and register for the bond while contributing **no STX** to the position.

The min-ustx-ratio mechanism exists specifically to ensure a value-proportional STX bond backs every unit of staked sats (this is the on-chain analog of the report's dust/minimum-deposit floor, which also broke due to compounding decimal/integer-division assumptions). Here the equality that breaks is: *"every signer/staker reward-share weight granted for staked sBTC must be backed by a proportional, non-zero, slashable STX lock."* With the truncation bug, a staker can obtain reward-share weight and signer participation credit for sBTC stake while contributing `u0` STX collateral, i.e., "signing weight ... exceeding locked value."

### Impact Explanation
This falls in the High-severity bucket defined by the rules: "signing weight or reward slots exceeding locked value." An attacker can register (and, per the tests, roll forward across many bond periods) with real sBTC custody but no STX bond backing it, undermining the protocol's core collateralization assumption without needing any privileged role — only their own funds and dust-sized sats amounts, which is explicitly not excluded since the "attacker's own stake" exclusion applies to losses of the attacker's *own* funds, not to systemic under-collateralization of the shared reward/signer-weight accounting.

### Likelihood Explanation
The bug is a straightforward, always-reachable pure-function truncation triggered purely by choosing a small `sats-amount` relative to `stx-value-ratio`; no race conditions, no privileged calls, and no unusual protocol state are required — only that the staker be allowlisted for some sats amount via `setup-bond`'s existing allowlist path (an ordinary user-facing flow), then choose a low `sats-amount`/`amount-ustx=0` when calling `register-for-bond`.

### Recommendation
Compute the floor with a single combined multiplication before dividing, e.g.:
```clarity
(/ (* stx-value-ratio sats-amount min-ustx-ratio) (* u100 u10000))
```
and additionally enforce a non-zero floor (or reject registrations with `amount-ustx == u0`) whenever `sats-amount > u0`, so that the STX-collateral requirement cannot be defeated by rounding.

### Proof of Concept
1. `setup-bond` is called by the bond admin with `stx-value-ratio = 10`, `min-ustx-ratio` any value, and an allowlist entry granting the attacker `max-sats = 9` (or any `sats-amount` such that `stx-value-ratio * sats-amount < 100`).
2. Attacker computes off-chain: `min-ustx-for-sats-amount(9, 10, min-ustx-ratio) == u0` (verifiable directly against the formula at `pox-5.clar:3089-3095`).
3. Attacker calls `register-for-bond` with `amount-ustx = u0` and `btcLockup = (err sats-amount)` (transferring the small real sBTC amount into the contract).
4. The `asserts! (>= amount-ustx (min-ustx-for-sats-amount ...))` check passes because both sides are `u0`.
5. Attacker is now a registered bond member with sBTC custody and reward-share weight, but with `u0` STX locked as collateral — breaking the intended one-to-one backing invariant between staked sats and locked STX.

Note: I could not directly view the full body of `register-for-bond` (only surrounding tests and the floor function itself), so the exact comparison operator (`>=` vs `>`) and any additional minimum-amount guard elsewhere in the function are inferred from the test file's description rather than directly read; a Devin session with full file access should confirm this exact assertion before remediation.

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

**File:** contrib/core-contract-tests/tests/pox-5/commands/RegisterForBondErrInsufficientStx.ts (L18-24)
```typescript
/**
 * Register for a bond with one uSTX below the `min-ustx-for-sats-amount`
 * floor. The amount check is the first `asserts!` after the prepare-phase
 * guard, so a registrable bond outside the prepare phase reverts with
 * ERR_INSUFFICIENT_STX before the started / already-staked / too-much-sats
 * checks and mutates nothing.
 */
```
