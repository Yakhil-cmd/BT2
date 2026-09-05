### Title
Truncating integer division in `min-ustx-for-sats-amount` lets a staker back a sBTC protocol bond with near-zero STX collateral - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`pox-5.clar`'s `register-for-bond` requires that a staker locking `sats-total` sats of sBTC (or L1 BTC) also lock at least `min-ustx-for-sats-amount(sats-total, stx-value-ratio, min-ustx-ratio)` uSTX as collateral. That helper performs two sequential *floor* divisions, which can truncate to `0` for realistic parameter combinations, letting a staker satisfy the "sufficient STX" check with `amount-ustx = 0` (or a value far below the intended ratio) while still contributing real sats to the bond and receiving bond membership/reward shares.

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

The inner term `(/ (* stx-value-ratio sats-amount) u100)` truncates toward zero, and the result is used as the input to a second truncating division by `u10000`. For any `sats-amount` small enough that `stx-value-ratio * sats-amount < 100`, the inner division already yields `0`, and the whole expression evaluates to `0` regardless of `min-ustx-ratio`. Even for larger `sats-amount`, the two chained floor divisions can round the required uSTX down well below the intended `min-ustx-ratio` fraction of the bond's BTC value.

`register-for-bond` uses this value as the *only* gate on the amount of STX a staker must lock relative to the sats they are staking: [2](#0-1) 

```
;; Verify that they're sending enough STX
(asserts!
    (>= amount-ustx
        (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
            (get min-ustx-ratio bond)
        ))
    ERR_INSUFFICIENT_STX
)
```

Because the caller freely chooses `amount-ustx` (subject only to `>= 0` and to `>= total-balance`, both trivially satisfiable at `amount-ustx = 0`), a staker whose `sats-total` rounds the minimum to `0` can register with `amount-ustx = 0` uSTX locked. The bond membership is still recorded with the full `sats-total` sBTC/BTC custodied: [3](#0-2) 

and that same `sats-total` is what drives the staker's bond share/reward accounting (`add-staker-to-bond-cycles ... sats-total`), independent of the (possibly zero) `amount-ustx` locked via `add-staker-to-signer-cycles`. The `min-ustx-ratio` field on `protocol-bonds` exists specifically to enforce that STX collateral tracks BTC-denominated exposure (as documented in the comment above the function: "a minimum amount of STX that must be locked relative to BTC for this term"), but the arithmetic used to enforce it is defeated by rounding.

This mirrors the class of bug in the referenced SVT report: a pool/collateral computation that is supposed to enforce a proportional relationship between two asset amounts, but whose flawed (here: doubly-truncating) arithmetic lets an unprivileged caller drive the required counter-asset to zero while still receiving the benefit tied to the primary asset.

### Impact Explanation
This breaks the intended equality "STX locked ≥ min-ustx-ratio × BTC value staked" that `register-for-bond` is supposed to enforce for every bond membership. A staker can obtain a bond membership — and the associated sats-denominated reward shares and signer voting weight sourced from `sats-total` — while locking little or no STX collateral. This is a "signing weight or reward slots exceeding locked value" class issue (per the Impact rubric, High), since the staker's committed value-in-the-protocol (their locked STX, the collateral actually protecting the system/signers) is decoupled from the reward/weight they receive, which is instead driven by the sats amount alone.

### Likelihood Explanation
The check is reachable by any allow-listed staker calling the public `register-for-bond` entry point with attacker-chosen `amount-ustx` and `sats-total`/L1 lockup amount — no privileged role is required beyond being on the bond's allowlist, which is a normal precondition for any staker in this flow. Triggering the truncation only requires choosing (or being naturally assigned via `allowlist`) a `sats-amount` for which `stx-value-ratio * sats-amount < 100`, or more generally exploiting the compounding floor-division rounding for larger amounts — well within an ordinary user's control since they choose their own `amount-ustx`/`sats-total` pair.

### Recommendation
Perform the multiplication before any division and divide only once, at the end, using full precision (e.g., multiply by `PRECISION` first as pox-5 already does elsewhere for reward math) to avoid compounding truncation: e.g. `(/ (* stx-value-ratio sats-amount min-ustx-ratio) (* u100 u10000))`, and additionally consider rejecting `amount-ustx = 0` combined with `sats-total > 0`, or requiring a minimum computed value greater than zero whenever `sats-total > 0` and `min-ustx-ratio > 0`.

### Proof of Concept
1. Bond admin (or existing test fixtures) sets up a bond with some `stx-value-ratio` and `min-ustx-ratio`, e.g. `stx-value-ratio = 100`, `min-ustx-ratio = 1000` (10%).
2. Compute `sats-amount` such that `(stx-value-ratio * sats-amount) / 100 < 1`, e.g. `sats-amount = 0` is trivial but even nonzero small `sats-amount` (below `100/stx-value-ratio`) forces the inner division to `0`, making `min-ustx-for-sats-amount` return `0`.
3. Staker calls `register-for-bond` with that small `sats-total` (via sBTC path) and `amount-ustx = 0`.
4. The `>= amount-ustx (min-ustx-for-sats-amount ...)` check (`0 >= 0`) passes; `register-for-bond` proceeds, custodies the sBTC, and records a `protocol-bond-memberships` entry with `amount-ustx: 0` while the staker still accrues bond rewards keyed by `sats-total` via `add-staker-to-bond-cycles`.
5. Repeat across multiple small registrations (subject to allowlist `max-sats`) to accumulate sats-backed reward exposure with negligible aggregate STX collateral. [1](#0-0) [2](#0-1)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L712-719)
```text
        ;; Verify that they're sending enough STX
        (asserts!
            (>= amount-ustx
                (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
                    (get min-ustx-ratio bond)
                ))
            ERR_INSUFFICIENT_STX
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-805)
```text
        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
            amount-sats: sats-total,
        })
        (map-set protocol-bonds-total-staked bond-index
            (+ current-total-staked sats-total)
        )
        ;; A roll-over from an ending bond ADDS the new bond's shares but does
        ;; NOT tear down the old bond's per-cycle shares/delegation (unlike
        ;; `update-bond-registration`, which removes then re-adds).
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            BOND_LENGTH_CYCLES sats-total
        ))

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            BOND_LENGTH_CYCLES amount-ustx false
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
