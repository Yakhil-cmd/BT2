This confirms the analog: `redeem` computes payout via `convert-to-assets-preview` (which uses `total-assets` that counts outstanding debt at full nominal value via `total-debt`/index, with no markdown for expected loss), and is only capped by `get-available-assets` (idle liquidity = `assets - total-borrowed`), not by whether some borrower is already insolvent. The loss is only written into the shared `lindex`/`assets` state when `liquidate` → `socialize-debt` actually executes. This produces the same "escape via early exit" race described in the report.

### Title
LP depositors can front-run bad-debt socialization by redeeming vault shares before `liquidate` writes down the loss - ([File: mainnet/contracts/vault/v0-vault-usdc.clar])

### Summary
Zest's lending vaults (`v0-vault-usdc.clar`, `v0-vault-sbtc.clar`, etc.) price zToken redemptions using `convert-to-assets-preview`, which is based on `total-assets` — a value that counts the borrower's outstanding debt at full nominal value (`total-debt` = `principal-scaled * index`) regardless of whether that debt is already unrecoverable (undercollateralized). The vault's share price is only marked down when `market.clar`'s `liquidate` function determines "no collateral left" and calls `socialize-debt`, which writes down `lindex` in the vault. Because this markdown happens only inside a specific liquidation transaction — not automatically the instant a position becomes insolvent — any unprivileged LP can observe an under-collateralized position on-chain (via price movement) and call `redeem` to exit at the pre-loss share price before a liquidator submits the `liquidate` transaction that triggers `socialize-debt`. The remaining LPs absorb the entire loss when socialization finally occurs.

### Finding Description
`redeem` in the vaults (e.g. [1](#0-0) ) computes the payout `inkind` from `convert-to-assets-preview`, which is derived from `total-assets-preview`/`total-assets`. `total-assets` is defined as `current-assets + interest`, where `interest` comes from `total-debt` (`principal-scaled * index`) [2](#0-1) . Crucially, this valuation assumes ALL outstanding debt (including debt owed by an already insolvent borrower whose collateral has fallen below their debt) will be fully repaid — there is no discount for expected bad debt.

The only limiting check in `redeem` is `get-available-assets`, defined as idle liquidity `assets - total-borrowed` [3](#0-2)  — this bounds how much can be withdrawn but does not affect the exchange rate used, which remains at the pre-loss value.

The vault's share price is only marked down when the market's `liquidate` function determines the borrower has "no collateral left" and triggers `socialize-debt-asset` → `vault-socialize-debt`, which calls the vault's `socialize-debt` and writes down `lindex` proportionally to the loss [4](#0-3)  and [5](#0-4) .

Since `liquidate` is a permissionless call that must be separately submitted by a liquidator, there is an observable window — from the moment a borrower becomes insolvent (visible from oracle price data / position state) until a liquidator actually executes `liquidate` — during which any LP can `redeem` at the stale, pre-loss exchange rate. This mirrors exactly the "escaping losses by frontrunning the oracle updates" pattern from the StakeWise report: the loss event is publicly knowable before the shared accounting state (there, exchange rate; here, `lindex`) is updated to reflect it, letting early responders exit clean while later/remaining depositors bear the entire loss.

### Impact Explanation
This is a socialization mechanism (bad-debt loss meant to be shared among all vault suppliers) that can be selectively evaded by whichever LP redeems first, shifting a disproportionate/complete share of the loss onto the LPs who remain. This is a direct theft of user funds at rest for the remaining depositors (their principal is diminished by socialize-debt lindex write-down) while the front-runner exits whole, consistent with "socialization charged to all suppliers" being an in-scope impact.

### Likelihood Explanation
The insolvency-causing price movement is publicly observable on-chain (via Pyth/DIA feed updates or via monitoring collateral vs. debt ratios), and any depositor can immediately submit `redeem` without any special privilege, permission, or same-block requirement. Unlike the liquidation itself, which has an explicit same-block protection (`ERR-LIQUIDATION-BORROW-SAME-BLOCK`) [6](#0-5) , there is no analogous protection preventing `redeem` from racing ahead of `socialize-debt`. The likelihood scales with how much idle liquidity (`get-available-assets`) is present in the vault at the time — larger idle balances allow larger clean exits.

### Recommendation
- Track/estimate at-risk (potentially unrecoverable) debt continuously (e.g., mark down `total-assets` for positions that are below the full-liquidation LTV threshold) so `convert-to-assets-preview` reflects expected losses before `socialize-debt` executes.
- Alternatively, introduce a withdrawal delay/queue (similar to StakeWise's exit queue) so that redemptions cannot bypass losses that are already economically realized but not yet accounted on-chain.
- Consider pausing `redeem` for a vault once a tracked position's debt exceeds recoverable collateral value, until `liquidate`/`socialize-debt` resolves it.

### Proof of Concept
1. Alice and Bob each deposit into `v0-vault-usdc` (or any Zest vault), receiving zTokens.
2. A borrower's collateral price crashes (via Pyth oracle update) such that the borrower's debt now exceeds their collateral value — the position is insolvent but not yet liquidated.
3. Alice observes the price update on-chain and immediately calls `redeem`, which uses `convert-to-assets-preview` — still based on `total-assets` counting the (now-unrecoverable) debt at full value — to redeem her zTokens at the pre-loss exchange rate, subject only to `get-available-assets` idle liquidity.
4. A liquidator later calls `liquidate` on the insolvent borrower; since no collateral remains, `socialize-debt-asset`/`vault-socialize-debt` writes down `lindex`, reducing the value of all remaining zToken holders' shares (e.g. Bob's).
5. Bob, who did not redeem in time, absorbs the full write-down that Alice escaped, even though the loss should have been shared proportionally across all LPs present at the time of insolvency.

### Citations

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L795-819)
```text
(define-public (redeem (amount uint) (min-out uint) (recipient principal))
  (let (
    (states (var-get pause-states))
    (u (try! (accrue)))
    (account contract-caller)
    (current-assets (var-get assets))
    (balance (get-balance-internal account))
    (balance-check (asserts! (>= balance amount) ERR-INSUFFICIENT-BALANCE))
    (available-assets (get-available-assets))
    (inkind (convert-to-assets-preview amount)))

  (asserts! (>= current-assets inkind) ERR-INSUFFICIENT-ASSETS)
  (asserts! (not (get redeem states)) ERR-PAUSED)
  (asserts! (> amount u0) ERR-AMOUNT-ZERO)
  (asserts! (> inkind u0) ERR-OUTPUT-ZERO)
  (asserts! (>= inkind min-out) ERR-SLIPPAGE)
  (asserts! (>= available-assets inkind) ERR-INSUFFICIENT-LIQUIDITY)

  (try! (ft-burn? zft amount account))
  (try! (send-underlying inkind recipient))
  (var-set assets (- current-assets inkind))

  (print {
    action: "redeem",
    caller: contract-caller,
```

**File:** local-testing/contracts/vault/vault-usdc.clar (L332-346)
```text

(define-private (debt-preview)
  (calc-cumulative-debt (var-get principal-scaled) (next-index)))

(define-private (total-assets)
  (let ((current-assets (var-get assets))
        (debt (total-debt))
        (borrowed (var-get total-borrowed))
        (interest (if (> debt borrowed) (- debt borrowed) u0)))
    (+ current-assets interest)))

(define-private (total-assets-preview)
  (let ((current-assets (var-get assets))
        (debt (debt-preview))
        (borrowed (var-get total-borrowed))
```

**File:** local-testing/contracts/vault/vault-usdc.clar (L946-968)
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
    (var-set principal-scaled (if (> scaled-principal scaled-amount) (- scaled-principal scaled-amount) u0))
    (var-set total-borrowed (if (> borrowed principal-reduction) (- borrowed principal-reduction) u0))
    (var-set assets (if (> current-assets principal-reduction) (- current-assets principal-reduction) u0))
```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L479-484)
```text
(define-read-only (get-available-assets)
  (let ((current-assets (var-get assets))
        (borrowed (var-get total-borrowed)))
    (if (>= current-assets borrowed)
        (- current-assets borrowed)
        u0)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1428-1431)
```text
    ;; Oracle frontrunning protection: prevent same-block liquidation
    ;; This blocks flash-loan based attacks where user borrows + gets liquidated in same block
    (last-borrow-block (get last-borrow-block position))
    (same-block-check (asserts! (not (is-eq last-borrow-block stacks-block-height)) ERR-LIQUIDATION-BORROW-SAME-BLOCK))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1534-1560)
```text
      ;; Handle bad debt socialization if no collateral left
      (let ((bad-debt-socialized 
              (if no-collateral-left
                  (let ((stripped-debt-list (filter-out-debt-asset (get debt pos-full) debt-aid))
                        (fresh-debt-list (if (is-eq debt-updated u0)
                                             stripped-debt-list
                                             (unwrap-panic (as-max-len?
                                               (append stripped-debt-list
                                                       { aid: debt-aid, scaled: debt-updated })
                                               u64)))))
                    (if (> (len fresh-debt-list) u0) ;; if still has debt
                      (let ((socialization-result (fold socialize-debt-asset 
                                                        fresh-debt-list 
                                                        { borrower: borrower, success: true })))
                        (asserts! (get success socialization-result) ERR-BAD-DEBT-SOCIALIZATION-FAILED)
                        ;; emit bad-debt-socialized event
                        (print {
                          action: "bad-debt-socialized",
                          caller: contract-caller,
                          data: {
                            borrower: borrower,
                            debt-list: fresh-debt-list
                          }
                        })
                        true)
                      false))
                  false)))
```
