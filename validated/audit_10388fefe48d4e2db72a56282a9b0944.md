### Title
`min-ustx-for-sats-amount` truncates the STX collateral floor to zero via premature division - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`min-ustx-for-sats-amount` in `pox-5.clar` performs an inner division before the final multiplication, exactly the bug class described in the external report ("division should be performed after multiplication"). This truncates the required STX floor to zero whenever `stx-value-ratio * sats-amount < 100`, letting a staker register for (or roll over into) a bond while locking far less uSTX than the protocol's collateral rule requires.

### Finding Description
The function is defined as: [1](#0-0) 

```clarity
(define-read-only (min-ustx-for-sats-amount
        (sats-amount uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
    )
    (/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
)
```

The mathematically correct formula is `(stx-value-ratio * sats-amount * min-ustx-ratio) / (100 * 10000)`, but the implementation divides `(stx-value-ratio * sats-amount)` by `u100` *before* multiplying by `min-ustx-ratio`. Because Clarity's `uint` division truncates, this intermediate `(/ (* stx-value-ratio sats-amount) u100)` evaluates to `0` whenever `stx-value-ratio * sats-amount < 100`, regardless of `min-ustx-ratio`. The subsequent multiplication by `min-ustx-ratio` and division by `u10000` then also produce `0`, so the function returns `u0` — i.e., "no STX required at all" — instead of a small-but-nonzero floor.

The comment in the integration test confirms this function is used as the enforced STX floor when registering for a bond: [2](#0-1) 

This shows `amount-ustx >= min-ustx-for-sats-amount(sats, stx-value-ratio, min-ustx-ratio)` is the invariant the contract is meant to enforce so that each sat of sBTC staked into a bond is properly STX-collateralized per the bond's configured `stx-value-ratio`/`min-ustx-ratio`. `stx-value-ratio` is bond-admin controlled and `sats-amount` is attacker-influenced (bounded only by the staker's allowlist `max-sats`), so a staker can choose a small `sats-amount` (or the bond can simply have a low `stx-value-ratio`) such that `stx-value-ratio * sats-amount < 100`, making the on-chain enforced floor collapse to zero.

### Impact Explanation
This breaks the equality the protocol depends on: sats staked into a bond must be backed by a minimum amount of locked uSTX proportional to the bond's configured value ratio. With the floor truncated to zero, a staker can register sBTC into a bond while locking little or no STX, meaning the signer/staker obtains reward-earning bond shares (and associated `sbtc` yield accrual via `calculate-bond-rewards`/`get-earned`) without providing the STX collateral the protocol's economic design assumes. This matches the "signing weight or reward slots exceeding locked value" High-impact category — value is credited to a participant without the requisite locked backing.

### Likelihood Explanation
The condition `stx-value-ratio * sats-amount < 100` is easily reachable: an attacker only needs to choose (within their allowlisted `max-sats`) a sufficiently small `sats-amount` for a given bond's `stx-value-ratio`, or the exploit becomes trivial on bonds configured with low `stx-value-ratio`/`min-ustx-ratio` values. No privileged role is required — any allowlisted staker calling the public registration/rollover path that consults this read-only helper can trigger it.

### Recommendation
Reorder the arithmetic to multiply first and divide last, e.g.:
```clarity
(/ (* stx-value-ratio sats-amount min-ustx-ratio) (* u100 u10000))
```
This preserves precision and matches the same fix recommended in the original report (perform division after multiplication).

### Proof of Concept
1. Bond admin (or default bond config) sets `stx-value-ratio = r` and `min-ustx-ratio = m` for a bond.
2. Staker selects `sats-amount = s` such that `r * s < 100` (e.g., `r = 50`, `s = 1`, product `50 < 100`).
3. Calling `(min-ustx-for-sats-amount s r m)` evaluates `(/ (* 50 1) u100)` → `(/ 50 u100)` → `u0`, then `(/ (* u0 m) u10000)` → `u0`.
4. The staker registers for the bond via the public entrypoint with `amount-ustx = 0` (or any negligible amount), which now satisfies the buggy floor check, allowing `s` sats to be staked into the bond with no real STX backing while still accruing bond-cycle sBTC rewards proportional to `s`.

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

**File:** stacks-node/src/tests/pox_5_integrations.rs (L4356-4359)
```rust
    // `stx-value-ratio = 100` and `min-ustx-ratio = 10000`
    // (== 100% in basis points),
    // `min-ustx-for-sats-amount(SBTC_AMT, 100, 10000) = SBTC_AMT` ustx — so
    // any `amount-ustx >= SBTC_AMT` satisfies the bond's STX floor.
```
