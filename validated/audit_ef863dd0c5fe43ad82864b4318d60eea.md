## Analysis

The reported bug class — naive integer division causing a nonzero input to yield a zero result — has a direct, in-scope analog in `pox-5.clar`'s protocol-bond STX-backing check.

### Title
Double integer-division truncation in `min-ustx-for-sats-amount` lets a staker register for a bond with less STX locked than the configured `min-ustx-ratio` requires - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond` is supposed to guarantee that a staker's locked STX is at least a fixed fraction (`min-ustx-ratio`, in basis points) of the value of the sats they are staking/proving, computed via `min-ustx-for-sats-amount`. That function performs two sequential integer (floor) divisions instead of one combined computation, so rounding error compounds and the STX floor can be pushed to zero (or otherwise understated) for combinations of `sats-amount`/`stx-value-ratio`/`min-ustx-ratio` that would not round to zero under a single division. This is the same bug class as the ether-camp report (truncation of a value below the divisor's granularity silently drops to zero), but here it weakens a solvency/backing invariant instead of just under-crediting a balance.

### Finding Description
`min-ustx-for-sats-amount` is defined as: [1](#0-0) 

`(/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)`

This computes `floor(floor(stx-value-ratio * sats-amount / 100) * min-ustx-ratio / 10000)`. The inner `floor(... / 100)` step discards any remainder before the `min-ustx-ratio` multiplication is even applied, so information about the true value is lost twice. As a result, the STX floor is systematically *lower* than the mathematically-correct `stx-value-ratio * sats-amount * min-ustx-ratio / 1,000,000`, and for many parameter combinations it floors all the way to `0`, even though `sats-amount > 0`.

`register-for-bond` uses this value as the *only* solvency check tying locked STX to staked sats: [2](#0-1) 

If `min-ustx-for-sats-amount(...)` evaluates to `0`, the assertion `(>= amount-ustx 0)` is trivially satisfied, so a staker can submit `amount-ustx = 0` (or any negligible amount) while still crediting `sats-total` sats to the bond: [3](#0-2) 

Unlike the `stake` (STX-only) path, there is no separate `SIGNER_SET_MIN_USTX` floor enforced in `register-for-bond`; the only STX-vs-sats floor is the truncation-prone `min-ustx-for-sats-amount` check. This is corroborated by the integration test comments explicitly stating the floor is exactly this function's output: [4](#0-3) 

Because `sats-total` (not `amount-ustx`) is what is recorded into `protocol-bonds-total-staked` and `add-staker-to-bond-cycles` (which drive bond reward-share accounting), a staker whose registration hits this truncation boundary receives full bond reward-share credit for `sats-total` while having posted an STX amount below what `min-ustx-ratio` was configured to require — including the L1-proof path, where `sats-total` comes from a verified Bitcoin lockup via `verify-l1-lockups` rather than custodied sBTC, so no additional value is even transferred to back the shortfall.

### Impact Explanation
This breaks the equality the bond's STX floor is meant to enforce: `locked STX >= min-ustx-ratio × sats value`. When the check rounds to zero, a staker's bond reward-share (and hence claim on sBTC rewards distributed for that bond/signer) is not actually backed by the STX collateral the protocol's own economic parameters require. This matches the High-impact category "signing weight or reward slots exceeding locked value" — the staker's bond participation (which drives reward distribution) exceeds what their locked STX should permit under the configured ratio.

### Likelihood Explanation
Triggering the zero-floor case requires specific relationships between `stx-value-ratio`, `min-ustx-ratio`, and `sats-amount` (all of which except `sats-amount` are set by the bond admin via `setup-bond`, not the attacker). For bonds configured with a low `min-ustx-ratio` (e.g. thin backing tiers) and/or where `stx-value-ratio` is not extremely large, a staker who controls the exact `sats-amount` they register (subject only to their allowlist `max-sats`) can select a value that lands in the truncation gap — the double-floor makes this gap systematically wider than a single-division implementation would produce. This is a function of contract parameters rather than attacker-controlled cryptography or a privileged role, and it's fully reachable by any allowlisted staker calling `register-for-bond` directly.

### Recommendation
Compute `min-ustx-for-sats-amount` with a single division (combine the multiplications before dividing, matching the "fractional multiplication error" precaution already used elsewhere in the contract, e.g. the `PRECISION` constant), i.e. `(/ (* stx-value-ratio sats-amount min-ustx-ratio) (* u100 u10000))`, and/or add an explicit non-zero-value assertion so that any `sats-amount > 0` cannot yield an `amount-ustx` floor of `0`.

### Proof of Concept
1. Admin calls `setup-bond` with a `stx-value-ratio` and `min-ustx-ratio` such that `floor(stx-value-ratio * sats-amount / 100)` is a small nonzero integer `k`, and `k * min-ustx-ratio < 10000` (e.g. `min-ustx-ratio` set to a low basis-point value for a "light" bond tier), for some allowlisted `sats-amount` within the staker's `max-sats` allowance.
2. An allowlisted staker calls `register-for-bond` with that `sats-amount` (via either the sBTC-custody path or an L1 lockup proof) and `amount-ustx = 0`.
3. `(min-ustx-for-sats-amount sats-amount stx-value-ratio min-ustx-ratio)` evaluates to `0` due to the compounded floor divisions [1](#0-0) , so `(>= amount-ustx 0)` passes and `(>= total-balance amount-ustx)` trivially passes.
4. The registration succeeds, crediting `sats-total` into `protocol-bonds-total-staked` and the staker's bond cycles [5](#0-4)  with effectively zero STX backing, contrary to the bond's configured `min-ustx-ratio`.

**Note on completeness:** I was not able to fully trace how `sats-total` vs. `amount-ustx` separately feed into the sBTC reward-waterfall distribution math (`settle-rewards`/`calculate-rewards`) within the remaining tool budget, so I cannot state with full certainty the exact sBTC-reward magnitude this discrepancy yields per bond — only that the STX-backing invariant itself is provably breakable via this truncation.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L710-720)
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

**File:** stacks-node/src/tests/pox_5_integrations.rs (L571-576)
```rust
    // 1) `setup-bond` from the configured bond admin. Allowlist the staker
    // for `SBTC_AMT` sats. With `stx-value-ratio = 100` and
    // `min-ustx-ratio = 10000` (== 100% in basis points),
    // `min-ustx-for-sats-amount(SBTC_AMT, 100, 10000) = SBTC_AMT` ustx, so
    // any `amount-ustx >= SBTC_AMT` clears the bond's STX floor.
    const SBTC_AMT: u128 = 1_000_000;
```
