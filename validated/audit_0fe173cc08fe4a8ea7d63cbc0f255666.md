### Title
LPs can front-run a `liquidate()` bad-debt event by calling `redeem()` first, shifting socialized losses onto remaining depositors - ([File: mainnet/contracts/vault/v0-vault-sbtc.clar])

### Summary
Zest v2 vaults price zToken redemptions off a shared `lindex` (liquidity index) that is written down atomically and non-gradually whenever a liquidation leaves a borrower with `no-collateral-left`, via `socialize-debt`. Any address holding zTokens can watch the mempool for a pending `liquidate()` call that will trigger bad-debt socialization and front-run it with `redeem()`, exiting at the pre-loss exchange rate. The loss that should have been shared pro-rata across all zToken holders is instead concentrated on the depositors who did not (or could not) react in time.

### Finding Description
Vault share pricing (`convert-to-assets-preview` / `convert-to-shares-preview`) is driven by `lindex`, which normally moves smoothly through time-based interest accrual in `accrue()`. However, `socialize-debt` performs a **discrete, single-transaction write-down** of `lindex` proportional to the fraction of `total-assets` lost to bad debt: [1](#0-0) 

This function is invoked from within `market.clar`'s `liquidate()` path whenever a borrower's position has no collateral left after seizure, via the `socialize-debt-asset` fold over the borrower's remaining debt assets: [2](#0-1) 

The `redeem()` function on the vault has no cooldown, no pending-liquidation check, and simply reads the *current* `lindex`/`total-assets` at execution time to compute the payout: [3](#0-2) 

Because `liquidate()` is a normal, publicly visible transaction (subject to normal mempool visibility before confirmation), any zToken holder can observe an impending liquidation that will produce `no-collateral-left` (e.g., after watching an oracle price update that pushes a large borrower's LTV to 100%+ collateral value), and submit `redeem()` ahead of the `liquidate()` transaction in the same or an earlier block. This lets the attacker capture the pre-write-down exchange rate and completely avoid absorbing their pro-rata share of the loss that `socialize-debt` is about to apply to `lindex`.

### Impact Explanation
The shared state here is the vault's `lindex`/`total-assets`, which determines the exchange rate for every zToken holder (`convert-to-assets-preview`/`convert-to-shares-preview`). Bad-debt socialization is designed to spread losses across **all** current zToken holders proportionally. An attacker who front-runs `redeem()` extracts full value before the write-down, converting what should be a shared loss into a loss borne disproportionately by the remaining, unaware LPs — a direct case of "socialization charged to all suppliers" being subverted by one unprivileged principal (the front-runner) at the expense of another (the remaining depositors). This is a theft of principal/unclaimed yield from the victims who are left holding a devalued `zft` position.

### Likelihood Explanation
Likelihood is moderate-to-high: liquidations are publicly triggerable transactions with visible preconditions (oracle price crossing a threshold, position LTV, absence of remaining collateral), so a bot watching prices/positions can predict an imminent `no-collateral-left` liquidation and race to redeem beforehand. No special privilege or flashloan is required — only monitoring of oracle price updates and mempool/chain state, plus normal zToken ownership.

### Recommendation
- Apply bad-debt socialization pro-rata to all shares *before* processing any redemption in the same block/epoch, or snapshot `lindex` for redemptions pending against a to-be-liquidated position.
- Consider a short redemption delay or a "loss accrual checkpoint" that locks in socialization impact prior to allowing withdrawals for that block, similar to how the same-block borrow/liquidate protection was added (`ERR-LIQUIDATION-BORROW-SAME-BLOCK`) — an analogous same-block guard could delay `redeem()` execution relative to a triggered `socialize-debt` call, or make `socialize-debt` retroactively adjustable for the block in which it occurs.
- Alternatively, add withdrawal queuing/batching so that all outstanding redeem requests within a settlement window share the same post-socialization exchange rate.

### Proof of Concept
1. Bob and other LPs supply USDC to `vault-usdc` (or `v0-vault-usdc`), receiving `zft` shares priced at the current `lindex`.
2. Alice's sBTC-collateralized USDC position becomes deeply undercollateralized (e.g., oracle price crash) such that a liquidation would leave `no-collateral-left`.
3. Charlie (liquidator) broadcasts `liquidate(alice, sbtc, usdc, ...)`; this transaction is visible before confirmation and will trigger `socialize-debt-asset` → `socialize-debt` on `vault-usdc`, writing down `lindex`: [4](#0-3) 
4. A malicious LP ("Mallory") who holds `zft` shares sees this pending transaction and submits `redeem()` on `vault-usdc`, which is ordered/confirmed before or in the same block as `liquidate()`, computing payout at the pre-write-down `lindex`: [5](#0-4) 
5. `liquidate()` then executes and calls `socialize-debt`, reducing `lindex` for all remaining `zft` holders. Mallory has escaped the loss entirely; Bob and other LPs who remained absorb a larger-than-proportional share of the bad debt because the total-assets base against which the loss is spread has shrunk by Mallory's exit.

### Citations

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L795-821)
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
    data: {
      redeemer: account,
```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L942-965)
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
