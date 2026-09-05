### Title
Double floor-division in `min-ustx-for-sats-amount` allows systematic under-collateralization of protocol bonds — (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`min-ustx-for-sats-amount` computes the minimum uSTX a staker must lock to back a given sBTC (`sats-amount`) contribution to a protocol bond, using the configured `stx-value-ratio` and `min-ustx-ratio`. The function performs **two chained integer (floor) divisions** instead of a single division, compounding rounding-down error in the same way the PoolTogether report describes for `_yieldVault`'s round-down share math. This lets a staker register (or top up) a bond with less uSTX than the protocol's intended minimum collateralization ratio, so the sats they custody are backed by an under-computed STX floor — i.e. locked STX value ends up below what `min-ustx-ratio` was designed to guarantee for that sats commitment.

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

The correct (single-rounding) mathematical formula would be `(stx-value-ratio * sats-amount * min-ustx-ratio) / (100 * 10000)`. Instead, the contract first computes `(stx-value-ratio * sats-amount) / u100` (rounding down, loses up to 99/100 of a unit), then multiplies that already-truncated intermediate result by `min-ustx-ratio` and divides again by `u10000` (rounding down a second time, loses up to 9999/10000 of a unit). This double-truncation systematically produces a **smaller** minimum-uSTX floor than the single-division formula would, for the same inputs — analogous to the report's root cause where chained round-down operations understate a value that gates a solvency/collateralization check.

This floor value is the exact quantity used by `register-for-bond` (and the STX-insufficiency guard exercised by the `RegisterForBondErrInsufficientStx` test) to reject stakers whose `amount-ustx` is below the computed minimum: [2](#0-1) 

Because the on-chain floor is itself already rounded down twice, a staker can lock exactly that (artificially low) `amount-ustx` and pass the check, while remaining under the value the protocol's `min-ustx-ratio` parameter was intended to enforce.

### Impact Explanation
`min-ustx-for-sats-amount` is the sole collateralization backstop tying a staker's custodied sBTC (`amount-sats`) to a required STX lock in `protocol-bond-memberships`: [3](#0-2) 

The bond membership's `amount-ustx` feeds directly into per-cycle signer delegation weight and staker share accounting used for reward distribution (`calculate-bond-rewards`, `get-total-shares-staked-for-cycle`), so under-collateralized bonds let stakers acquire signer weight / reward-earning stake backed by less locked STX than the protocol's own `min-ustx-ratio` configuration requires. This matches the "signing weight or reward slots exceeding locked value" High-impact category — the enforced floor is provably weaker than the intended economic minimum due to compounded rounding.

### Likelihood Explanation
The effect is deterministic and reproducible on every `register-for-bond` call (and any other caller of `min-ustx-for-sats-amount`); no special conditions or races are needed. The magnitude of the shortfall per call is small (bounded by two floor-division remainders), but it is systematic across all bond registrations, and small-`sats-amount`/`min-ustx-ratio` combinations amplify the relative loss (e.g., `min-ustx-ratio` values near the granularity of the `u10000` denominator can zero out the whole contribution before the second division).

### Recommendation
Combine the multiplication before dividing, performing a single rounding step (and consider rounding up, not down, for a minimum-requirement check):
```
(/ (* stx-value-ratio sats-amount min-ustx-ratio) u1000000)
```
or, to round up conservatively for a floor/minimum check:
```
(let ((numerator (* stx-value-ratio sats-amount min-ustx-ratio)))
  (/ (+ numerator u999999) u1000000))
```
This removes the compounded truncation and ensures the enforced STX minimum never falls below the value implied by `stx-value-ratio` and `min-ustx-ratio`.

### Proof of Concept
1. Deployer calls `setup-bond` with `stx-value-ratio = R` and `min-ustx-ratio = M` such that `(R * sats-amount) mod 100 != 0` and the truncated intermediate times `M` also loses precision when divided by `u10000`.
2. Staker computes `floor_min = min-ustx-for-sats-amount(sats-amount, R, M)`, which is strictly less than `ceil((R * sats-amount * M) / 1000000)` — the value the protocol's ratio parameters intend as the true minimum.
3. Staker calls `register-for-bond` with `amount-ustx = floor_min` and `btc-lockup` matching `sats-amount`; the `ERR_INSUFFICIENT_STX` check (as exercised in `RegisterForBondErrInsufficientStx.ts`) passes because it compares against the same under-computed `floor_min`, not the true ratio-implied minimum.
4. The staker's bond membership is recorded with `amount-sats = sats-amount` backed by `amount-ustx` below the intended collateralization ratio, and this membership subsequently earns signer weight and bond rewards proportional to `amount-sats`/`amount-ustx` shares that are not fully backed per the protocol's own `min-ustx-ratio` design.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L139-148)
```text
(define-map protocol-bond-memberships
    principal
    {
        bond-index: uint,
        amount-ustx: uint,
        signer: principal,
        is-l1-lock: bool,
        amount-sats: uint,
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

**File:** contrib/core-contract-tests/tests/pox-5/commands/RegisterForBondErrInsufficientStx.ts (L56-69)
```typescript
          // Smallest sats making the floor at least 1: solve
          // (((svr*sats)/100)*mur)/10000 >= 1 for sats, then add extra. Even
          // when both ratios are 1 this keeps the floor positive.
          const ratioProduct = config.stxValueRatio * config.minUstxRatio;
          const minSatsForFloor =
            (1_000_000n + ratioProduct - 1n) / ratioProduct;
          const sats = minSatsForFloor + r.extraSats;
          const minUstx = minUstxForSats(
            sats,
            config.stxValueRatio,
            config.minUstxRatio,
          );
          // One uSTX under the floor: the exact value that trips the check.
          const amountUstx = minUstx - 1n;
```
