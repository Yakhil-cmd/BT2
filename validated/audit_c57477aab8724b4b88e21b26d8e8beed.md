### Title
Borrower can indefinitely DoS its own liquidation by front-running with a trivial same-block borrow, exploiting the unconditional `last-borrow-block` check - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`liquidate()` unconditionally reverts with `ERR-LIQUIDATION-BORROW-SAME-BLOCK` whenever the target borrower has performed *any* `borrow()` call in the current block — regardless of amount, health, or intent. Because `borrow()` requires only `amount > 0` and post-borrow health, a borrower who sees an incoming liquidation transaction in the mempool can front-run it with a trivial borrow (e.g. the smallest possible unit of any enabled debt asset) to poison `last-borrow-block` for the current block and force the liquidator's transaction to revert, even though the position remains genuinely unhealthy and legitimately liquidatable.

### Finding Description
`borrow()` updates the account's `last-borrow-block` on every successful call via `debt-add-scaled`: [1](#0-0) 

`liquidate()` then unconditionally checks this field against the current block height and reverts if they match, with no fallback, tolerance, or way for the liquidator to route around it: [2](#0-1) 

The stated purpose of this check is to prevent flash-loan-style attacks where a user borrows and is instantly liquidated within the same block (oracle-manipulation defense): [3](#0-2) 

However, the guard is triggered by *any* borrow of *any* size, not specifically by borrows that materially change the health/oracle state. `borrow()` only requires `amount > 0` and that the post-borrow position stays healthy — it does not require a minimum economically meaningful amount: [4](#0-3) [5](#0-4) 

This means a borrower whose position has since become unhealthy (LTV crossed `ltv-liq-partial`) can still call `borrow()` for a tiny amount of a *different*, currently-healthy asset (or any asset where the position is still under the borrow-time LTV threshold) purely to refresh `last-borrow-block`, blocking any `liquidate()` call targeting them in that block. Unlike the `min-collateral-expected` slippage guard (which the liquidator sets and controls), `ERR-LIQUIDATION-BORROW-SAME-BLOCK` is an unconditional revert the liquidator cannot parametrize away.

Attacker: the borrower under threat of liquidation.
Victim: the liquidator (and indirectly the protocol, since delayed liquidation of an unhealthy position increases bad-debt risk as collateral value continues to fall).
Shared state: the borrower's `last-borrow-block` field in `market-vault`/`v0-market-vault`, written by `borrow()` and read by `liquidate()` — a classic case of one caller (borrower) priming shared state that is consumed adversarially against a different caller (liquidator) in the same block.

### Impact Explanation
Without the attacker's front-run transaction, the liquidator's `liquidate()` call succeeds: bad debt is repaid, collateral seized, and the position's health restored/improved.

With the attacker's front-run (a 1-wei-equivalent `borrow()` call), the liquidator's transaction unconditionally reverts, wasting the liquidator's gas and leaving the unhealthy position unliquidated for that block. Because the check operates per-block and the borrower can repeat this every block the position remains liquidatable (as long as they can front-run reliably), this can be used to persistently delay liquidation of an underwater position, letting bad debt grow as collateral price continues to decline — a temporary (and potentially compounding) freezing of the liquidator's ability to seize collateral and repay debt, which can escalate protocol bad-debt exposure. This lands in the temporary freezing of funds impact category.

### Likelihood Explanation
Likelihood is Medium: the attack requires the borrower to detect the pending liquidation transaction and front-run it in the same block (achievable via mempool monitoring or, on Stacks, transaction ordering awareness), and to repeat this every block they wish to delay liquidation, incurring gas costs each time. This mirrors the judged severity rationale in the referenced report — it is not automatic, but it is cheap, repeatable, and requires no special privilege, unlike the original Venus finding where the honest liquidator's own repay amount became invalid; here the mechanism is a purpose-built same-block guard that the borrower can trigger deliberately against themselves to stall an otherwise-legitimate liquidation.

### Recommendation
Scope the same-block protection to be state-aware rather than an unconditional block-based flag: e.g., only block liquidation if the *specific* debt/collateral pair or oracle price used in `liquidate()` was affected by the same-block borrow, or require the blocking borrow to have moved LTV by a meaningful (non-negligible) threshold. Alternatively, track the block of the last borrow *of the asset actually being repaid/seized* rather than a single account-wide flag, and/or allow the liquidator to bypass the check when the position's LTV was already above `ltv-liq-full`/`ltv-liq-partial` at the start of the block (i.e., unhealthy before any same-block borrow occurred).

### Proof of Concept
1. Borrower Alice has a position with LTV above `ltv-liq-partial` (liquidatable).
2. Liquidator Charlie submits `liquidate(alice, ...)`.
3. Alice detects Charlie's pending transaction and submits `borrow(some-ft, 1, none, none)` for a trivial amount of any asset where her position remains healthy under `LTV-BORROW`, ordered before Charlie's transaction in the same block.
4. `debt-add-scaled` sets `last-borrow-block: stacks-block-height` for Alice's account: [1](#0-0) 
5. Charlie's `liquidate(alice, ...)` executes in the same block; `same-block-check` fires and the whole transaction reverts with `ERR-LIQUIDATION-BORROW-SAME-BLOCK`: [6](#0-5) 
6. Alice's position remains unliquidated despite being genuinely unhealthy; she can repeat step 3 in subsequent blocks to continue stalling liquidation.

### Citations

**File:** mainnet/contracts/market/v0-market-vault.clar (L442-450)
```text
(define-public (debt-add-scaled (account principal) (scaled-amount uint) (asset-id uint))
  (let ((states (var-get pause-states))
        (entry (resolve-or-create account))
        (user-id (get id entry))
        (mask (get mask entry))
        (update-mask (mask-update mask asset-id false true)) ;; debt, insert
        ;; Oracle frontrunning protection: record current block when borrowing
        (updated-entry (merge entry { mask: update-mask, last-update: stacks-block-time, last-borrow-block: stacks-block-height }))
        (result (add-user-scaled-debt user-id asset-id scaled-amount)))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1269-1272)
```text
    ;; preconditions
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)
    (asserts! (get debt asset) ERR-BORROW-DISABLED)
    (asserts! (is-healthy collateral-value debt-value current-ltvb) ERR-UNHEALTHY)
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1289-1296)
```text
    (try! (vault-system-borrow asset-id amount funds-receiver))
    (let ((scaled-debt-added (convert-to-scaled-debt asset-id amount true))
          (borrow-index (get index (unwrap-panic (get-cached-indexes asset-id)))))
      (try! (contract-call? .v0-market-vault
                            debt-add-scaled
                            account
                            scaled-debt-added
                            asset-id))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1428-1435)
```text
    ;; Oracle frontrunning protection: prevent same-block liquidation
    ;; This blocks flash-loan based attacks where user borrows + gets liquidated in same block
    (last-borrow-block (get last-borrow-block position))
    (same-block-check (asserts! (not (is-eq last-borrow-block stacks-block-height)) ERR-LIQUIDATION-BORROW-SAME-BLOCK))

    ;; health check (FAIL-FAST) 
    ;; Check position is liquidatable BEFORE calling calc-liq-factor
    (health-check  (asserts! (>= current-ltv ltv-liq-partial) ERR-HEALTHY))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1451-1454)
```text
    (debt-decimals (get debt-decimals debt-info))

    ;; collateral processing
    (user-coll-balance (find-collateral-amount (get collateral pos-full) coll-aid))
```
