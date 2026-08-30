## Title
Silent-failure collateral deposit via non-reverting SIP-010 `(ok false)` response bypasses `try!` check, allowing phantom-collateral borrowing against other lenders' pooled liquidity - (File: `mainnet/contracts/market/v0-market-vault.clar`)

### Summary
`collateral-add` in `v0-market-vault.clar` accepts a `<ft-trait>` and calls `receive-tokens`, whose result is only checked with `try!`. In Clarity, `try!` treats any `(ok ...)` response — including `(ok false)` — as success and continues execution; it only short-circuits on `(err ...)`. This mirrors the RealityCards `H-01` bug class: a token whose transfer function returns a boolean instead of reverting on failure. If any asset accepted as collateral behaves this way (returns `(ok false)` rather than aborting), `collateral-add` will credit the caller's collateral balance without the vault ever receiving the tokens.

### Finding Description
`receive-tokens` is defined as a thin passthrough to the trait's `transfer`: [1](#0-0) 

`collateral-add` calls it and only wraps the call in `try!`, then unconditionally credits the account's collateral via `add-user-collateral`/`insert`: [2](#0-1) 

`try!` in Clarity only aborts on an `err` response — a SIP-010-compliant-looking `transfer` implementation that returns `(ok false)` on failure (rather than aborting the transaction) passes `try!` silently. The actual boolean payload of the `(ok bool)` response is never inspected; there is no `(asserts! (is-eq result true) ...)` check anywhere in `collateral-add`. This is a direct structural analog of the RealityCards `topupMarketBalance`/`balancedBooks` bug: the code assumes the transfer "worked" whenever it doesn't produce an on-chain error, but the ERC20/SIP-010 boolean-return convention does not guarantee that.

An attacker who deposits an asset behaving this way can accrue collateral value in the shared market ledger (`collateral` map, `mask`) without any tokens actually entering `v0-market-vault`. Since `collateral-add` is the same accounting entry point used across all users of that asset for borrowing power, the attacker can subsequently borrow against this phantom collateral from the shared debt/liquidity pool funded by other lenders (via `v0-4-market.clar`'s borrow flow, which reads the collateral map populated here). If the attacker then walks away from the debt, the loss is socialized across all suppliers of the borrowed asset — the victims are other depositors/lenders whose funds back the borrow, not the attacker.

### Impact Explanation
This lands on **Critical — protocol insolvency / theft of user funds**: phantom collateral lets an attacker borrow real assets pooled from other users without posting real backing, directly draining the shared liquidity pool and leaving bad debt that other suppliers absorb.

### Likelihood Explanation
Likelihood depends entirely on whether any asset admitted to the market's collateral/asset registry can return `(ok false)` on a failed transfer instead of aborting. The report explicitly notes this is a well-documented, historically real behavior in some ERC20-like tokens (and is not guaranteed to be absent from every SIP-010 asset added to the market over time, since asset listing is an ongoing governance action, not a one-time code guarantee). The code contains no defensive check for this case, so the exploit is trivial to execute the moment such an asset is present — no special privilege is required.

### Recommendation
After every `receive-tokens`/`send-tokens` call in `v0-market-vault.clar`, explicitly assert on the returned boolean, e.g. `(asserts! (try! (receive-tokens ft amount account)) ERR-COLLATERAL-TRANSFER-FAILED)`, instead of relying on `try!` alone (which the constant `ERR-COLLATERAL-TRANSFER-FAILED` at line 36 suggests was originally intended but is not enforced in `collateral-add`). Apply the same fix to `send-tokens` usage in `collateral-remove`.

### Proof of Concept
1. A SIP-010 asset `X` is (or becomes) accepted as collateral, and its `transfer` function returns `(ok false)` when the caller lacks sufficient balance/allowance, rather than raising an `err`.
2. Attacker, holding zero balance of `X`, calls `collateral-add` with `ft` = asset `X` contract and an arbitrary `amount`.
3. `receive-tokens` calls `X`'s `transfer`, which returns `(ok false)`; `try!` at line 387 accepts this as success and continues.
4. `add-user-collateral`/`insert` records `amount` of asset `X` as the attacker's collateral, with no tokens having moved into the vault.
5. Attacker calls the market's borrow function against this phantom collateral, draining real assets from the pool funded by other depositors, leaving the pool under-collateralized/insolvent for that debt. [3](#0-2)

### Citations

**File:** mainnet/contracts/market/v0-market-vault.clar (L30-36)
```text
(define-constant ERR-AUTH (err u600001))
(define-constant ERR-PAUSED (err u600002))
(define-constant ERR-AMOUNT-ZERO (err u600003))
(define-constant ERR-INSUFFICIENT-COLLATERAL (err u600004))
(define-constant ERR-INSUFFICIENT-DEBT (err u600005))
(define-constant ERR-UNTRACKED-ACCOUNT (err u600006))
(define-constant ERR-COLLATERAL-TRANSFER-FAILED (err u600007))
```

**File:** mainnet/contracts/market/v0-market-vault.clar (L256-257)
```text
(define-private (receive-tokens (asset <ft-trait>) (amount uint) (account principal))
  (contract-call? asset transfer amount account current-contract none))
```

**File:** mainnet/contracts/market/v0-market-vault.clar (L374-404)
```text
(define-public (collateral-add (account principal) (amount uint) (ft <ft-trait>) (asset-id uint))
  (let ((states (var-get pause-states))
        (entry (resolve-or-create account))
        (user-id (get id entry))
        (mask (get mask entry))
        (updated-mask (mask-update mask asset-id true true)) ;; collateral, insert
        (updated-entry (merge entry (refresh updated-mask)))
        (result (add-user-collateral user-id asset-id amount)))

    (try! (check-impl-auth))
    (asserts! (not (get collateral-add states)) ERR-PAUSED)
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)

    (try! (receive-tokens ft amount account))
    
    (insert updated-entry)

    (print {
      action: "collateral-add",
      caller: contract-caller,
      data: {
        account: account,
        asset-id: asset-id,
        amount: amount,
        updated-collateral-amount: result,
        mask-before: mask,
        mask-after: updated-mask
      }
    })
      
    (ok result)))
```
