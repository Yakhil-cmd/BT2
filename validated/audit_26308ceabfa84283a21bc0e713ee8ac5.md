### Title
Self-liquidation lets a borrower extract the liquidation penalty bonus from their own collateral without an independent liquidator bearing risk - ([File: mainnet/contracts/market/v0-4-market.clar])

### Summary
`liquidate` in `mainnet/contracts/market/v0-4-market.clar` never checks that `borrower` differs from the caller (`liquidator`/`contract-caller`). A user can call `liquidate` against their own position, becoming both the liquidatee and the liquidator, and route the seized collateral to themselves via `collateral-receiver`.

### Finding Description
`liquidate` computes `liquidator contract-caller` and later derives `actual-receiver (match collateral-receiver recv recv liquidator)` [1](#0-0) [2](#0-1) . The full list of preconditions checked before execution is:

```
(asserts! (not (is-liquidation-paused debt-aid)) ERR-LIQUIDATION-PAUSED)
(asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)
(asserts! (> debt-amount u0) ERR-AMOUNT-ZERO)
(asserts! (> debt-to-repay u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
(asserts! (> coll-final u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
(asserts! (>= coll-final min-collateral-expected) ERR-SLIPPAGE)
``` [3](#0-2) 

None of these forbid `borrower` being equal to `contract-caller`. Contrast this with the codebase's own security posture elsewhere: the collateral-add egroup-transition guard is explicitly documented as blocking "self-liquidation exploits (manipulating egroup to trigger liquidation with penalty)" [4](#0-3) , and there is a dedicated test suite (`EG-02: Cannot self-liquidate via egroup transition`) that validates that specific vector is blocked [5](#0-4) . This shows the protocol's designers considered self-liquidation an attack to prevent, but the guard only covers the egroup-transition path, not a direct call to `liquidate` where the position is already liquidatable through ordinary means (e.g., price drop). No `asserts!` in `liquidate` itself rejects `borrower == contract-caller`.

Economically, `liquidate` computes `coll-final` to be strictly greater (in USD terms) than `debt-to-repay`, because `liq-penalty` (`liq-penalty-min`..`liq-penalty-max`) is added on top of the repaid debt value via `calc-final-liquidation-amounts`/`process-collateral-asset` before scaling `debt-remove-scaled`/`collateral-remove` against the borrower's stored balances [6](#0-5) . This bonus is the entire economic incentive intended to compensate an *independent, at-risk* liquidator for repaying someone else's bad debt. If the borrower is the caller, they simply move `coll-final` (worth `debt-to-repay` plus the penalty) from their locked collateral balance to their own wallet while only reducing their own recorded debt by `debt-to-repay`, i.e., they unilaterally extract the liquidation-penalty spread from the pool's collateral accounting without any counter-party actually assuming liquidation risk.

### Impact Explanation
This falls under "seizure exceeding its bound": the amount of collateral released to the caller exceeds what is economically justified relative to the debt actually repaid, and that excess (the liquidation bonus) is siphoned by the position owner rather than being paid to an independent liquidator who took on risk. Since collateral/debt accounting inside `market-vault` backs the claims of all depositors/lenders in that asset pool, unjustified extraction of the bonus by the borrower degrades the collateralization backing other users' claims - a value transfer from the pool (and, by extension, other depositors) to the self-liquidating attacker. This is a "temporary/permanent freezing or theft" adjacent harm to third parties (other suppliers of the pool), meeting the High impact bar (theft of value belonging to other depositors) rather than being purely self-harm, since it degrades the shared collateral backing.

### Likelihood Explanation
Likelihood is high: no special conditions beyond having a position that has crossed `ltv-liq-partial` are required, and the same-block/oracle-frontrunning checks (`same-block-check`) do not prevent this since the position is already unhealthy through legitimate accrual/price movement, not same-block borrow-then-liquidate. Any user willing to let/push their own position into the partial-liquidation zone can call `liquidate` on themselves and immediately extract the bonus.

### Recommendation
Add an explicit check in `liquidate` (mirroring the intent already documented for the egroup-transition guard) that rejects the transaction when `contract-caller` (or `tx-sender`) equals `borrower`, e.g. `(asserts! (not (is-eq contract-caller borrower)) ERR-SELF-LIQUIDATION)`. Apply the same check in `liquidate-redeem` and `liquidate-multi`'s `call-liquidate` path.

### Proof of Concept
1. Alice deposits sBTC collateral and borrows USDC up to a safe LTV (as in `local-testing/tests/flows/liquidation/liquidation-basic.test.ts`) [7](#0-6) .
2. sBTC price drops so Alice's LTV crosses `ltv-liq-partial`, making her position eligible for `liquidate` per the health check `(asserts! (>= current-ltv ltv-liq-partial) ERR-HEALTHY)` [8](#0-7) .
3. Alice (instead of a third-party liquidator) calls `liquidate` with `borrower = alice`, `collateral-receiver = (some alice)`, supplying her own USDC to repay `debt-to-repay`.
4. `vault-system-repay` pulls USDC from Alice (contract-caller) [9](#0-8) ; `debt-remove-scaled` reduces Alice's own recorded debt; `collateral-remove` sends `coll-final` sBTC to `actual-receiver` = Alice [10](#0-9) .
5. Because `coll-final`'s USD value includes `liq-penalty` on top of `debt-to-repay`, Alice receives back collateral worth more than the debt she repaid, extracting the liquidation bonus from her own recorded position without any third party bearing liquidation risk - value that should instead have gone only to an independent liquidator, at the expense of the shared collateral pool backing other depositors.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L1392-1392)
```text
    (liquidator contract-caller)
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1433-1435)
```text
    ;; health check (FAIL-FAST) 
    ;; Check position is liquidatable BEFORE calling calc-liq-factor
    (health-check  (asserts! (>= current-ltv ltv-liq-partial) ERR-HEALTHY))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1453-1493)
```text
    ;; collateral processing
    (user-coll-balance (find-collateral-amount (get collateral pos-full) coll-aid))
    (coll-info (process-collateral-asset coll-aid debt-actual-usd liq-penalty 
                                         user-coll-balance assets coll-asset))
    (coll-actual (get coll-actual coll-info))
    (coll-expected (get coll-expected coll-info))
    (coll-price (get coll-price coll-info))
    (coll-decimals (get coll-decimals coll-info))

    ;; final liquidation amounts (with proportional adjustment if needed)
    (final-amounts (calc-final-liquidation-amounts
                     debt-actual-usd coll-actual coll-expected
                     coll-price coll-decimals
                     debt-price debt-decimals liq-penalty))
    (debt-final-usd (get debt-final-usd final-amounts))
    (debt-final (get debt-final final-amounts))

    ;; debt scaling for storage
    (curr-scaled (get-account-scaled-debt borrower debt-aid))
    (scaled-info (scale-debt-for-liquidation debt-final coll-actual curr-scaled debt-aid))
    (scaled-to-remove (get scaled-to-remove scaled-info))
    (debt-to-repay (get debt-to-repay scaled-info))
    (coll-final-raw (get coll-final scaled-info))
    (coll-remaining (- user-coll-balance coll-final-raw))
    (remaining-debt-to-repay
      (if (> coll-remaining u0)
        (let ((rem-coll-usd (normalize (* coll-remaining coll-price) coll-decimals false))
              (rem-debt-usd (div-bps-down rem-coll-usd (+ BPS liq-penalty-max)))
              (rem-debt-tokens (mul-div-down rem-debt-usd (pow u10 debt-decimals) debt-price))
              (rem-borrow-index (get index (unwrap-panic (get-cached-indexes debt-aid))))
              (rem-scaled (mul-div-down rem-debt-tokens INDEX-PRECISION rem-borrow-index)))
          (mul-div-up rem-scaled rem-borrow-index INDEX-PRECISION))
        u1))
    (coll-final (if (is-eq remaining-debt-to-repay u0) user-coll-balance coll-final-raw)))

    (asserts! (not (is-liquidation-paused debt-aid)) ERR-LIQUIDATION-PAUSED)
    (asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)
    (asserts! (> debt-amount u0) ERR-AMOUNT-ZERO)
    (asserts! (> debt-to-repay u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (> coll-final u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (>= coll-final min-collateral-expected) ERR-SLIPPAGE)
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1496-1496)
```text
    (try! (vault-system-repay debt-aid debt-to-repay debt-ft debt-address))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1499-1512)
```text
    (let ((debt-updated (try! (contract-call? .v0-market-vault
                              debt-remove-scaled
                              borrower
                              scaled-to-remove
                              debt-aid)))
          ;; Collateral receiver defaults to liquidator if not specified
          (actual-receiver (match collateral-receiver recv recv liquidator))
          (coll-removed (try! (contract-call? .v0-market-vault
                              collateral-remove
                              borrower
                              coll-final
                              collateral-ft
                              coll-aid
                              actual-receiver)))
```

**File:** docs/High-Level-Overview.md (L103-106)
```markdown
**Attack Scenarios Prevented**:
- Dust collateral poisoning (adding tiny amounts to worsen position)
- Self-liquidation exploits (manipulating egroup to trigger liquidation with penalty)
- Accidental position deterioration (users can't make themselves liquidatable by adding collateral)
```

**File:** local-testing/tests/security/egroup.test.ts (L105-123)
```typescript
  describe("EG-02: Cannot self-liquidate via egroup transition", () => {
    it("should prevent egroup transition that makes position liquidatable", async () => {
      // Alice creates position at high but safe LTV with 70% egroup
      txOk(market.collateralAdd(contracts.sbtc.identifier, 100000000n, null), alice); // 1 sBTC = $60k
      txOk(market.borrow(contracts.usdc.identifier, 41000000000n, null, null), alice); // $41k at 68% LTV
      
      // Position is healthy (68% < 70% borrow threshold, < 85% liquidation threshold)
      // But adding USDC would transition to 60% LTV egroup, making it unhealthy
      
      // Attack: Try to add dust USDC
      const result = txErr(market.collateralAdd(contracts.usdc.identifier, 1000000n, null), alice);
      
      // Should fail because capacity check prevents harmful transitions
      // Current capacity: $60k * 70% = $42k
      // Future capacity: $60k * 60% = $36k < $41k (violates)
      expect(cvToValue(result.result).value).toBe('400005'); // ERR-UNHEALTHY
      
      console.log("✓ Self-liquidation via egroup transition blocked");
    });
```

**File:** local-testing/tests/flows/liquidation/liquidation-basic.test.ts (L89-106)
```typescript
    // STEP 1: Alice deposits 1 sBTC as collateral
    const sbtcAmount = 100000000n; // 1 BTC (8 decimals)
    txOk(sbtcToken.mint(sbtcAmount, alice), deployer);
    txOk(market.collateralAdd(sbtcToken.identifier, sbtcAmount, null), alice);
    
    console.log('✓ Alice deposited 1 sBTC as collateral ($60,000 value)');
    
    // STEP 2: Alice borrows $42,000 USDC (70% LTV - healthy)
    const borrowAmount = 42000000000n; // $42,000 USDC (6 decimals)
    txOk(market.borrow(usdcToken.identifier, borrowAmount, alice, null), alice);
    
    console.log('✓ Alice borrowed $42,000 USDC (70% LTV - healthy)');
    
    // Initial position:
    // - Collateral: 1 BTC @ $60,000 = $60,000
    // - Debt: $42,000 USDC
    // - LTV: (42,000 / 60,000) * 100 = 70%
    
```
