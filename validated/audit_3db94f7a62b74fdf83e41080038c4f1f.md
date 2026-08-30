### Title
Fee-on-transfer collateral tokens are credited at nominal `amount` instead of actual received balance, letting an attacker socialize under-collateralized debt onto shared lenders - ([File: mainnet/contracts/market/v0-market-vault.clar])

### Summary
`collateral-add` in `v0-market-vault.clar` credits a user's on-chain collateral ledger with the caller-supplied `amount` *before* actually pulling the tokens via `receive-tokens`, and `receive-tokens` never verifies that the contract's real token balance increased by `amount`. If the collateral asset (an SIP-010 `ft-trait` implementation approved for the market) takes a fee on transfer, the vault records more collateral than it actually holds, letting the depositor borrow against phantom collateral that is ultimately backed by the shared lending pool.

### Finding Description
In `collateral-add`, the collateral map is updated with the full nominal `amount` via `add-user-collateral`, and only afterwards is `receive-tokens` called to pull the funds: [1](#0-0) 

`receive-tokens` performs a plain `transfer` call and trusts the nominal `amount` with no post-transfer balance check: [2](#0-1) 

The caller-facing `market.clar`/`v0-4-market.clar` `collateral-add` wrapper uses this same nominal `amount` for LTV/health checks (`get-asset-value`, `future-coll-usd`), and to permit new borrowing capacity: [3](#0-2) 

Because the collateral ledger is a per-user map (`collateral { id, asset } -> amount`), the attacker cannot directly overwrite another user's entry. However, the collateral asset being credited is not actually escrowed 1:1 with real tokens the vault holds — if the token asset takes a fee on transfer, the vault contract only ever receives `amount - fee`, yet the market's health/LTV checks, and the amount available for borrowing, use the full nominal `amount`. The attacker can then borrow against the market's shared debt pool (funded by all suppliers/lenders across the market) up to a capacity that is not actually backed by real assets. When the attacker's debt is not repaid (default/liquidation with insufficient real collateral to seize), the shortfall is socialized across all lenders whose deposited liquidity backs that market — the victims are the other unprivileged liquidity suppliers, not just the caller.

### Impact Explanation
This falls under "temporary/permanent freezing of funds" and potential "protocol insolvency": lenders supplying liquidity to the market that the attacker borrows from bear a shortfall they did not cause, once the attacker's under-collateralized position is liquidated and fails to fully cover the debt taken from the shared pool. This directly parallels the referenced Popcorn `MultiRewardEscrow.lock` finding: the contract records `amount` in its accounting struct without verifying the true amount received, and later obligations (there: claim payout; here: LTV-based borrowing capacity secured against the shared pool) are computed from the inflated recorded value rather than the true balance.

### Likelihood Explanation
Likelihood depends on whether the DAO ever whitelists a fee-on-transfer SIP-010 token as a collateral asset via the `ft-trait` interface (`collateral-add` accepts any `<ft-trait>` implementer resolved through `get-asset`). Currently supported production collateral assets (STX/wSTX, sBTC, stSTX, USDC, USDH, stSTXbtc, and the corresponding zTokens) are not known fee-on-transfer tokens, so exploitability today is low, but the code path itself performs no defensive check (e.g., balance-before/balance-after verification) and will silently misbehave for any future fee-on-transfer asset addition — a class of bug the referenced report specifically flags as needing to not be assumed away.

### Recommendation
In `receive-tokens` (and the analogous `receive-underlying` deposit paths in the vault contracts), measure the contract's actual token balance before and after the `transfer` call and use the delta (actual received amount) — not the caller-supplied nominal `amount` — when crediting `add-user-collateral` / `assets`/ shares-minted accounting. Alternatively, explicitly document and enforce (e.g., via an allow-list check or assertion) that only standard, non-fee-charging SIP-010 tokens can ever be onboarded as collateral/vault-underlying assets.

### Proof of Concept
1. DAO (hypothetically) onboards a fee-on-transfer SIP-010 token `FEE-TOKEN` as a new collateral asset via `get-asset`/asset registry.
2. Attacker calls `collateral-add` with `amount = 1000` `FEE-TOKEN`. `v0-market-vault.collateral-add` executes `add-user-collateral user-id asset-id 1000`, recording 1000 units of collateral for the attacker, then calls `receive-tokens`, which only actually pulls `1000 - fee` tokens into the vault (e.g., 950 if a 5% fee).
3. The market's LTV/health checks in `v0-4-market.clar`/`market.clar` (`get-asset-value`, `future-coll-usd`) treat the attacker's collateral as 1000 units, letting them borrow against the full nominal value from the shared lending pool.
4. Attacker borrows the maximum permitted debt and defaults. Liquidation can only seize the 950 real tokens the vault holds, leaving the pool's other lenders short by the fee-adjusted difference across all such collateral deposits, socializing the loss.

### Citations

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

**File:** mainnet/contracts/market/v0-4-market.clar (L1094-1099)
```text
        caller: contract-caller,
        data: {
          account: account,
          asset-id: asset-id,
          asset-addr: ft-address,
          amount: amount,
```
