### Title
`socialize-debt` can permanently zero the liquidity index, freezing yield/value for all other zToken/vault depositors - ([File: local-testing/contracts/vault/vault-usdc.clar] and equivalent vault-*.clar / mainnet v0-vault-*.clar)

### Summary
The GDA report flags a shared pricing value (`spotPrice`) that is updated without a floor check, letting it settle at a degenerate value that persists indefinitely and mispricing every future counterparty. Zest's vault `socialize-debt` function has the same structural flaw on `lindex` (the liquidity index that prices every zToken/rehypothecated-collateral holder in that vault): the write-down computation has no floor other than an exact-zero fallback, and once `lindex` hits `u0` it can never recover, because every later accrual only ever multiplies the existing index by a positive multiplier (`0 * multiplier = 0` forever).

### Finding Description
In every vault contract (`vault-usdc.clar`, `vault-sbtc.clar`, `vault-stx.clar`, `vault-ststx.clar`, `vault-usdh.clar`, `vault-ststxbtc.clar`, and their mainnet `v0-vault-*.clar` counterparts), `socialize-debt` computes the new liquidity index as: [1](#0-0) 

```clarity
(new-lindex (if (and (> old-total-assets u0) (> old-total-assets debt-reduction))
               (mul-div-down current-lindex (- old-total-assets debt-reduction) old-total-assets)
               u0)))
...
(var-set lindex new-lindex)
```

If the socialized `debt-reduction` (bad debt being written off) is greater than or equal to `old-total-assets`, `new-lindex` is set to exactly `u0` with no minimum-value validation, analogous to `GDACurve` never checking the newly computed spot price against `MIN_PRICE`.

Once `lindex` is `u0`, it never recovers: `next-liquidity-index` always computes `(calc-index-next lidx multiplier)` starting from the stored `lidx`, and multiplying `0` by any `multiplier` yields `0`: [2](#0-1) 

This `lindex` is not a caller-local value — it is global vault state consumed by every other user of the vault. `market.clar`'s `resolve-ztoken` prices all zToken collateral for *every* borrower in the protocol using this same cached `lindex`: [3](#0-2) 

```clarity
(define-private (resolve-ztoken (p uint) (aid uint))
  (let ((cached (unwrap! (get-cached-indexes aid) ERR-ORACLE-CALLCODE))
        (cached-lindex (get lindex cached))
        (scaled (* p cached-lindex)))
    (ok (div-down scaled INDEX-PRECISION))))
```

So the moment one borrower's liquidation triggers `socialize-debt-asset` → `vault-socialize-debt` with `debt-reduction >= old-total-assets` for a given vault (e.g. `vault-usdc`), that vault's `lindex` is zeroed. From that point forward:
- Every zToken holder (e.g. `zUSDC`) of that vault has their collateral valued at `0` in every health/borrow/liquidation calculation — a permanent freeze of their collateral value.
- Interest accrual to suppliers for that vault permanently stops producing positive yield (index stuck at 0 forever), because `calc-index-next` can never move `0` off `0`.

### Impact Explanation
This is a shared-state harm: the borrower whose position gets liquidated/socialized (or, in the worst case, an attacker who deliberately drives one vault's `total-assets` toward zero via a crafted bad-debt liquidation) permanently damages every other unrelated zToken depositor and supplier in that vault. The victims are unprivileged third parties (existing/future zToken holders and liquidity suppliers of the affected vault) who never authorized or triggered the write-down. This falls under "temporary/permanent freezing of funds" (High/Critical) since deposited liquidity's yield-bearing representation is priced to zero indefinitely with no built-in floor or governance recovery path evident in the write-down logic itself.

### Likelihood Explanation
Triggering `debt-reduction >= old-total-assets` requires a scenario where a single liquidation's bad-debt socialization consumes the entire remaining `total-assets` of a vault — most plausible in a small/newly-seeded vault or one experiencing a severe price crash (as the repo's own bad-debt test scenario intentionally exercises via `mock-oracle` price crashes, see `local-testing/tests/security/liquidation.test.ts`). This makes it a low-liquidity/high-lambda-style edge case, structurally the same likelihood class as the original GDA report (extreme parameter combinations, not everyday operation), but reachable without any privileged action — liquidation is a public, permissionless function.

### Recommendation
Introduce a minimum-index floor (analogous to `MIN_PRICE`/`validateSpotPrice` in the GDA fix) in `socialize-debt` across all vault contracts: never let `new-lindex` fall to (or below) a protocol-defined minimum non-zero value, and/or cap the socialized `debt-reduction` so `old-total-assets - debt-reduction` cannot reach zero for the index computation, reverting or partially socializing instead of zeroing out the index that all other depositors depend on.

### Proof of Concept
1. Vault `vault-usdc` has `total-assets = X` and is thinly seeded (e.g., new vault, small early liquidity).
2. A borrower using `USDC` debt against volatile collateral (e.g., `sBTC`) becomes deeply underwater after a price crash (as in `local-testing/tests/security/liquidation.test.ts`'s bad-debt scenario).
3. `liquidate` is called; because no collateral remains to cover the debt, `market.clar` calls `socialize-debt-asset` → `vault-usdc socialize-debt scaled-amount` with a `debt-reduction` computed to be `>= old-total-assets`.
4. Inside `socialize-debt`, `new-lindex` resolves to `u0` and is stored via `(var-set lindex new-lindex)`.
5. Any other user holding `zUSDC` collateral, or any subsequent depositor, now has `resolve-ztoken` return `0` for their zUSDC valuation forever (`market.clar:365-369`), and `next-liquidity-index` in `vault-usdc.clar:394-406` can never move the index off zero. [1](#0-0) [4](#0-3) [3](#0-2)

### Citations

**File:** local-testing/contracts/vault/vault-sbtc.clar (L946-965)
```text
(define-public (socialize-debt (scaled-amount uint))
  (let ((scaled-principal (var-get principal-scaled))
        (borrowed (var-get total-borrowed))
        (idx (var-get index))
        (current-assets (var-get assets))
        (current-lindex (var-get lindex))
        (old-total-assets (total-assets))
        (debt-reduction (mul-div-down scaled-amount idx INDEX-PRECISION))
        (principal-reduction (if (> scaled-principal u0)
                                (mul-div-down scaled-amount borrowed scaled-principal)
                                u0))
        ;; Write down lindex proportionally to loss in total-assets
        (new-lindex (if (and (> old-total-assets u0) (> old-total-assets debt-reduction))
                       (mul-div-down current-lindex (- old-total-assets debt-reduction) old-total-assets)
                       u0)))

    (try! (check-caller-auth))
    (asserts! (> scaled-amount u0) ERR-AMOUNT-ZERO)

    (var-set lindex new-lindex)
```

**File:** local-testing/contracts/vault/vault-usdc.clar (L381-406)
```text
(define-private (next-index)
  (let ((states (var-get pause-states))
        (idx (var-get index)))
    (if (get accrue states)
        idx
        (let (
            (rate (interest-rate))
            (time-delta (- stacks-block-time (var-get last-update)))
            (multiplier (if (is-eq time-delta u0)
                          INDEX-PRECISION
                          (calc-multiplier-delta rate time-delta true))))
          (calc-index-next idx multiplier)))))

(define-private (next-liquidity-index)
  (let ((states (var-get pause-states))
        (lidx (var-get lindex)))
    (if (get accrue states)
        lidx
        (let (
            (rate (interest-rate))
            (liquidity-rate (calc-liquidity-rate rate (utilization) (var-get fee-reserve)))
            (time-delta (- stacks-block-time (var-get last-update)))
            (multiplier (if (is-eq time-delta u0)
                          INDEX-PRECISION
                          (calc-multiplier-delta liquidity-rate time-delta false))))
          (calc-index-next lidx multiplier)))))
```

**File:** local-testing/contracts/market/market.clar (L365-369)
```text
(define-private (resolve-ztoken (p uint) (aid uint))
  (let ((cached (unwrap! (get-cached-indexes aid) ERR-ORACLE-CALLCODE))
        (cached-lindex (get lindex cached))
        (scaled (* p cached-lindex)))
    (ok (div-down scaled INDEX-PRECISION))))
```
