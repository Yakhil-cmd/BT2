### Title
LP depositors can front-run `liquidate`'s bad-debt socialization by redeeming before the loss is applied - ([File: mainnet/contracts/vault/v0-vault-sbtc.clar])

### Summary
When a borrower's position becomes fully underwater (`no-collateral-left`), `liquidate` in `v0-4-market.clar` calls `socialize-debt` on the relevant debt vault, which permanently writes down `assets` and `lindex` — the state that determines the exchange rate between vault shares (zTokens) and underlying assets for every depositor. Because `redeem` on the vault is a completely separate, unprivileged, permissionless transaction that uses whatever `lindex`/`assets` value is currently on-chain, any depositor who sees an under-collateralized position sitting in the mempool waiting to be liquidated can front-run the liquidator's `liquidate` call with their own `redeem` call, exiting at the pre-loss exchange rate and shifting their share of the bad debt onto the depositors who remain in the vault.

### Finding Description
The debt vaults (`vault-sbtc.clar`, `vault-stx.clar`, `vault-usdc.clar`, `vault-usdh.clar`, `vault-ststx.clar`, `vault-ststxbtc.clar`, and their mainnet `v0-*` equivalents) expose `redeem`, which converts a depositor's zToken shares to underlying assets using the current `assets`/`lindex` state: [1](#0-0) 

Bad debt is only socialized when a liquidation call determines that a borrower has no collateral left to seize. `liquidate` in the market computes `no-collateral-left`, and only then invokes `socialize-debt-asset`/`socialize-debt` on the affected vault, which writes down `lindex` (and therefore all future exchange-rate calculations) proportionally to the loss: [2](#0-1) [3](#0-2) 

The write-down of `lindex`/`assets` happens atomically inside the `liquidate` transaction, but `redeem` is a normal, permissionless, unrelated transaction with no dependency on or awareness of pending liquidations. Because the borrower's under-collateralized position and pending `liquidate` call are both visible on-chain/in the mempool before the socialization actually executes, any depositor can simply submit `redeem` with higher priority/fee to withdraw their shares at the current (pre-write-down) rate before `socialize-debt` executes. This is directly analogous to the Celo `LockedGold.slash` issue: a penalty (bad debt) is destined to be applied to a shared pool of value, but an unprivileged party who sees it coming can extract their portion of that value first, shifting the cost onto everyone who does not (or cannot) also front-run.

- Attacker: any LP/depositor of the affected vault who is watching the chain/mempool.
- Victim: all other depositors remaining in the vault who hold zTokens through the socialization event.
- Shared state: the `assets` and `lindex` variables in the vault contract, which determine the shares↔asset exchange rate used by every depositor's `redeem`/`convert-to-assets-preview` call.

### Impact Explanation
This is a temporary/permanent freezing (loss) of funds for the remaining suppliers: the write-down that should be spread proportionally across all zToken holders at the time of the bad debt event is instead concentrated onto whoever fails to withdraw in time, because the attacker's redemption is settled at a stale, higher exchange rate. This matches the in-scope "socialization charged to all suppliers" pattern and is High severity (temporary/permanent freezing of funds for the remaining LPs) — the aggregate loss booked by `socialize-debt` is fixed, so any value the front-runner extracts above their fair share is value the remaining pool must absorb.

### Likelihood Explanation
Likelihood is meaningful but bounded by visibility and reaction time: it requires (1) a position becoming severely underwater and pending `liquidate` (a public, deterministic, oracle/price-visible event), and (2) a depositor able to react and submit `redeem` with sufficient liquidity available in `available-assets` before the socializing `liquidate` transaction lands. Because prices are updated on-chain/oracle feeds and liquidation eligibility is publicly computable ahead of the triggering price update or liquidation tx, sophisticated LPs/bots can realistically monitor and front-run this in the same block or in the window between an oracle price drop and the liquidator's `liquidate` call.

### Recommendation
Consider one or more of:
1. Snapshot/reserve the expected bad-debt write-down at the point the position becomes unhealthy (or apply the write-down pre-emptively/optimistically) rather than only at the moment `liquidate` executes, so `redeem`'s exchange rate cannot be computed favorably relative to the pending loss.
2. Introduce a withdrawal cooldown/queue or a partial "loss accrual" mechanism that continuously marks positions that would create bad debt against the vault's `assets`/`lindex`, so `redeem` always reflects the worst-case realizable value.
3. Alternatively, cap redemption amounts or add a grace-period pause on `redeem` for a vault when one of its debt positions is already at or beyond `LTV-LIQ-FULL`, forcing socialization to occur (or be provisioned for) before further redemptions are processed.

### Proof of Concept
1. Borrower opens a position with sBTC collateral and borrows USDC up to a level that is currently healthy.
2. sBTC price crashes (via oracle update) such that the position's collateral value falls far below its debt — a state that produces `no-collateral-left = true` on the next `liquidate` call (as exercised in the repo's own test, `ATK-LG-05: Bad debt cannot be artificially created`) [4](#0-3) .
3. Before any liquidator's `liquidate` transaction (which would trigger `socialize-debt-asset` → `socialize-debt`, writing down `lindex`/`assets`) is confirmed, an LP holding zUSDC shares submits `redeem` with a higher fee to be mined first.
4. The LP's `redeem` executes at the pre-write-down `lindex`/`assets` rate [5](#0-4) , extracting full value.
5. `liquidate` then executes, calling `socialize-debt` and marking down `lindex`/`assets` for the *remaining* zUSDC supply [2](#0-1) , so the loss that would otherwise have been shared with the front-running LP is now absorbed entirely by the LPs who did not exit first.

### Citations

**File:** local-testing/contracts/vault/vault-sbtc.clar (L799-819)
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
```

**File:** local-testing/contracts/vault/vault-sbtc.clar (L946-968)
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

**File:** local-testing/tests/security/liquidation.test.ts (L153-189)
```typescript
  describe("ATK-LG-05: Bad debt cannot be artificially created", () => {
    it("should socialize bad debt when collateral is exhausted", async () => {
      // Setup: Alice has small collateral, large debt
      txOk(market.collateralAdd(sbtcToken.identifier, 100000000n, null), alice); // 1 sBTC
      txOk(market.borrow(usdcToken.identifier, 42000000000n, null, null), alice); // $42k
      
      // Crash price severely to create bad debt scenario
      // At $10k per BTC: collateral = $10k, debt = $42k (massive underwater)
      await set_price(PythFeedIds.BTC, scalePriceForPyth(10000, -8), -8, deployer);
      
      const charlieSbtcBefore = rov(sbtcToken.getBalance(charlie)).value!;
      
      // Charlie tries to liquidate - will seize all collateral but not cover all debt
      txOk(
        market.liquidate(
          alice,
          sbtcToken.identifier,
          usdcToken.identifier,
          50000000000n, // Try to liquidate $50k (more than debt)
          0n,
          null,
          null
        ),
        charlie
      );
      
      const charlieSbtcAfter = rov(sbtcToken.getBalance(charlie)).value!;
      const collateralSeized = charlieSbtcAfter - charlieSbtcBefore;
      
      // Should have seized all of Alice's collateral (1 BTC)
      expect(collateralSeized).toBeLessThanOrEqual(100000000n);
      
      // Bad debt should be socialized (verified by liquidation succeeding)
      // The protocol handled the bad debt rather than allowing it to corrupt the system
      
      console.log("✓ Bad debt properly socialized when collateral exhausted");
    });
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L799-819)
```text
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
