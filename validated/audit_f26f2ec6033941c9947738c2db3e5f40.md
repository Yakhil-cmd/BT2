This confirms the design invariant that resolves the question: the `check-egroup-invariant` in `egroup.clar` guarantees that a **superset mask always has LTV values ≤ subset mask's LTV values** (i.e., a position with more asset types is never allowed a *more lenient* liquidation threshold than a position with fewer asset types), and the reverse holds for subsets (fewer assets → LTV ≥ superset's LTV, i.e., can only be more lenient or equal, never stricter). [1](#0-0) 

When A fully repays B's smallest debt asset (clearing the debt bit in `debt-remove-scaled`), B's mask shrinks to a **subset** of its previous mask. By the DAO-enforced invariant, the new (subset) egroup's `LTV-LIQ-PARTIAL`/`LTV-LIQ-FULL` must be **greater than or equal to** the old (superset) egroup's values — never stricter. [2](#0-1) 

So timing the exact block at which the mask-clearing branch fires cannot make B *more* liquidatable than before: removing debt (even 1 unit at a time) only ever reduces B's `total-debt-usd` and can only move B to an egroup with equal-or-looser liquidation thresholds. There is no code path by which A's precisely-timed dust on-behalf-of repayments can flip B into a *stricter* liquidation regime or freeze B's funds — the invariant is enforced at egroup-registration time specifically to rule out this "removing an asset flips risk against you" class of issue, and is verified off-chain before DAO approval per the audit scope's exclusions.

Additionally, `repay`/`debt-remove-scaled` never resolves or checks health/egroup status at all — it just reduces debt and updates the mask; liquidation eligibility is only evaluated later, independently, inside `liquidate`, which recomputes `total-debt-usd`/`total-collateral-usd` fresh against current price and current mask. Since A's dust repayments strictly monotonically decrease B's debt and B's egroup parameters can only loosen or stay equal as debt-asset bits clear, B's liquidation eligibility cannot be triggered *by A's repayments*, timed or not. The scenario in the question — A choosing the exact block boundary at which B "becomes liquidatable" via this mechanism — is not realizable under the current invariant enforcement. [3](#0-2) 

### No vulnerability found for this question.

### Citations

**File:** local-testing/contracts/registry/egroup.clar (L156-169)
```text
                  ;; determine relationship
                  (holds
                    (if (subset existing-mask new-mask)
                        ;; new is proper superset | LTVn <= LTVe
                        (and (<= new-ltv-borrow existing-ltv-borrow)
                             (<= new-ltv-liq-partial existing-ltv-liq-partial)
                             (<= new-ltv-liq-full existing-ltv-liq-full))
                        (if (subset new-mask existing-mask)
                            ;; existing is proper superset | LTVn >= LTVe
                            (and (>= new-ltv-borrow existing-ltv-borrow)
                                 (>= new-ltv-liq-partial existing-ltv-liq-partial)
                                 (>= new-ltv-liq-full existing-ltv-liq-full))
                            ;; no subset relationship
                            true))))
```

**File:** local-testing/contracts/market/market-vault.clar (L473-482)
```text
(define-public (debt-remove-scaled (account principal) (scaled-amount uint) (asset-id uint))
  (let ((states (var-get pause-states))
        (entry (resolve account))
        (user-id (get id entry))
        (mask (get mask entry))
        (remaining (try! (remove-user-scaled-debt user-id asset-id scaled-amount)))
        (nmask (if (is-eq remaining u0)
                      (mask-update mask asset-id false false) ;; debt, remove
                      mask))
        (updated-entry (merge entry (refresh nmask))))
```

**File:** local-testing/tests/security/egroup.test.ts (L201-235)
```typescript
  describe("EG-05: Superset invariant prevents LTV inconsistencies", () => {
    it("should use existing egroups that respect superset invariant", async () => {
      // The standard egroups from proposalCreateMultipleEgroups enforce
      // the superset invariant: more collateral types = lower (or equal) LTV
      
      // sBTC coll + USDC debt: 70% LTV
      // sBTC+USDC coll + USDC debt: 60% LTV (superset has lower LTV ✓)
      
      // Test 1: sBTC collateral at 70%
      txOk(market.collateralAdd(contracts.sbtc.identifier, 100000000n, null), alice);
      txOk(market.borrow(contracts.usdc.identifier, 42000000000n, null, null), alice); // 70% works
      
      // Verify position
      const position1Result = rov(marketVault.getPosition(alice, 0xffffffffffffffffn));
      expect(position1Result.isOk).toBe(true);
      if (typeof position1Result.value === 'bigint') {
        throw new Error(`Failed to get position. Error: ${position1Result.value}`);
      }
      expect(position1Result.value.mask).toBe(EGROUP_MASKS.sbtc_usdc); // sBTC coll + USDC debt
      
      // Repay
      txOk(market.repay(contracts.usdc.identifier, 42000000000n, null), alice);
      
      // Test 2: With sBTC+USDC collateral, max is 60%
      txOk(market.collateralAdd(contracts.usdc.identifier, 10000000000n, null), alice);
      
      // Try to borrow 70% of total collateral ($70k) = $49k
      const result = txErr(market.borrow(contracts.usdc.identifier, 49000000000n, null, null), alice);
      expect(cvToValue(result.result).value).toBe('400005'); // ERR-UNHEALTHY (exceeds 60%)
      
      // But 60% works: $70k * 0.60 = $42k
      txOk(market.borrow(contracts.usdc.identifier, 42000000000n, null, null), alice);
      
      console.log("✓ Due to superset invariant: more collateral / debt types than previous group = always lower LTV");
    });
```
