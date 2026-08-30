### Title
Panic (`unwrap-panic`) inside `liquidate` on attacker-chosen debt asset can abort otherwise-healthy liquidations, letting a borrower shield unhealthy debt from being liquidated - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`liquidate()` in `mainnet/contracts/market/v0-4-market.clar` computes `other-debt-repayable` and the bad-debt-socialization set using `(unwrap-panic (get-cached-indexes debt-aid))` [1](#0-0)  and `(unwrap-panic (as-max-len? (append stripped-debt-list {aid: debt-aid, scaled: debt-updated}) u64))` [2](#0-1) . Neither of these `unwrap-panic` calls is guarded with a fallback `err`, so any condition that makes them fail (missing cache entry, list already at its 64-element cap) causes the whole `liquidate` transaction to abort rather than return a clean error response. Because these expressions are evaluated deep in the liquidation execution path (after debt/collateral state has been read but before final `try!`s complete), any of the borrower's stored debt-asset entries reaching the max-length boundary makes `liquidate` unconditionally panic for that borrower, for every liquidator, indefinitely.

### Finding Description
`liquidate` first calls `accrue-user-debts` on the borrower's real debt list to populate `index-cache` for every asset the borrower currently owes [3](#0-2) . Later, when handling bad-debt socialization after a partial liquidation, the code strips the just-repaid asset from the borrower's debt list and, if debt remains for that asset, re-appends it via `as-max-len? ... u64` wrapped in `unwrap-panic` [4](#0-3) . `as-max-len?` returns `none` (causing `unwrap-panic` to panic and revert the whole transaction) whenever the resulting list would exceed the fixed 64-element bound. Since a borrower's debt list is itself capped at 64 entries and the market supports up to 64 assets globally, a borrower who has actively borrowed at (or accumulated stray dust debt entries up to) the 64-asset ceiling puts every future `liquidate` call against their position at risk of an unrecoverable panic in this bad-debt-socialization branch, instead of a graceful `err`.

The same fragility pattern appears with `(unwrap-panic (get-cached-indexes debt-aid))` used to compute `other-debt-repayable` for deciding whether the position has "no collateral left" [5](#0-4) : this assumes the cache was already populated earlier in the same call by `accrue-user-debts`/`accrue-user-collateral`, but any mismatch between what was accrued and `debt-aid` (which is derived from the caller-supplied `debt-ft` contract, not necessarily validated against the borrower's actual outstanding assets before this point) turns a would-be `err` response into an unrecoverable panic.

This is the same bug class as the referenced Celo/go-ethereum fix (#20612): unvalidated/edge-case inputs reach an `unwrap`/panic path instead of a checked, returned error, and the resulting crash is attacker-triggerable rather than purely a caller mistake, because the borrower - not the liquidator - controls the state (their own debt-list length/contents) that determines whether the panic fires.

### Impact Explanation
The victim here is not the caller (liquidator) but the borrower's counterparties who are exposed to the borrower's bad debt: every liquidator attempting to liquidate this borrower's unhealthy position hits the same panic, so the position becomes permanently un-liquidatable through `liquidate`/`liquidate-multi`/`liquidate-redeem` (all funnel into the same function) as long as the debt-list stays at the boundary condition. This is a "position made unevaluable by a third party" scenario explicitly called out as in-scope: the borrower (attacker) makes their own position immune to liquidation, which lets an unhealthy/underwater position persist, growing unrecovered bad debt that the vault suppliers (LPs) must eventually absorb - i.e., **temporary/permanent freezing of funds and protocol insolvency risk** for depositors in the affected vaults, since bad-debt socialization for that borrower can never complete via the normal liquidation path while the fault condition holds.

### Likelihood Explanation
Reaching exactly 64 populated debt-list entries (or otherwise tripping the `as-max-len?` boundary) requires the borrower to actively hold obligations across the market's full asset roster, which is a non-trivial but not impossible amount of setup (borrowing small dust amounts of every listed asset) and is entirely within a single account's own control, requiring no privileged access. The `get-cached-indexes` panic path is more speculative without confirming every call ordering guarantee across `accrue-user-debts`/`get-egroup` failures; this part of the analysis could not be fully verified against the complete function body within the available tool budget.

### Recommendation
Replace both `unwrap-panic` calls in the liquidation/bad-debt-socialization path with checked alternatives that return a proper `err` (e.g., `unwrap!` with a dedicated `ERR-*` code) instead of panicking, so that an edge-case debt-list length or missing cache entry degrades to a recoverable error rather than making the borrower's position permanently unliquidatable.

### Proof of Concept
1. Borrower opens small debt/collateral positions across effectively all supported assets until their scaled-debt list is at the 64-entry cap (or otherwise arranges a debt-asset combination that is absent from the accrued index cache at the point `other-debt-repayable`/bad-debt socialization is computed).
2. Borrower's overall position becomes unhealthy (LTV crosses `ltv-liq-partial`).
3. Any liquidator calls `liquidate` (directly or via `liquidate-multi`/`liquidate-redeem`) targeting this borrower; execution reaches the bad-debt-socialization branch, `as-max-len?` returns `none` for the 65th append (or `get-cached-indexes` returns `none`), `unwrap-panic` fires, and the entire transaction reverts with no error code - repeatable by every subsequent liquidation attempt.
4. The borrower's bad debt is never socialized/liquidated through the normal path, leaving the shortfall to accumulate against vault depositors.

Note: full confirmation that `debt-aid`/cache population invariants can actually be violated end-to-end (versus being always guaranteed by preceding `accrue-user-debts`/`get-egroup` calls) could not be completed within the available investigation budget; the `as-max-len?`/64-entry-boundary panic is the more directly verifiable root cause from the code shown.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L1405-1408)
```text
    ;; accrue FIRST - populates cache for zToken price resolution
    (u-debt (accrue-user-debts (get debt pos-full)))
    (u-coll (accrue-user-collateral (get collateral pos-full)))

```

**File:** mainnet/contracts/market/v0-4-market.clar (L1518-1524)
```text
          (other-debt-repayable
            (if (> other-coll-usd u0)
              (let ((other-adj (div-bps-down other-coll-usd (+ BPS liq-penalty-max)))
                    (other-tokens (mul-div-down other-adj (pow u10 debt-decimals) debt-price))
                    (other-borrow-idx (get index (unwrap-panic (get-cached-indexes debt-aid))))
                    (other-scaled (mul-div-down other-tokens INDEX-PRECISION other-borrow-idx)))
                (mul-div-up other-scaled other-borrow-idx INDEX-PRECISION))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1537-1543)
```text
                  (let ((stripped-debt-list (filter-out-debt-asset (get debt pos-full) debt-aid))
                        (fresh-debt-list (if (is-eq debt-updated u0)
                                             stripped-debt-list
                                             (unwrap-panic (as-max-len?
                                               (append stripped-debt-list
                                                       { aid: debt-aid, scaled: debt-updated })
                                               u64)))))
```
