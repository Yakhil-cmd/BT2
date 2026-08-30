### No vulnerability found for this question.

**Rationale:** `vault-accrue` at `mainnet/contracts/market/v0-4-market.clar:189` dispatches strictly by a fixed `aid` (0–11, the six vault asset ids), and that `aid` is derived from `(get-asset address)` where `address = (contract-of ft)` [1](#0-0) . An attacker cannot make `vault-accrue` operate on an arbitrary vault by simply supplying an arbitrary `<ft-trait>` contract — `get-asset` must resolve the supplied contract-of address to a registered asset id in the DAO-controlled asset registry, so only the six legitimate, already-existing vaults are ever reachable, exactly as intended by the routing dispatcher [2](#0-1) .

The only genuinely shared state written during `repay`/`vault-accrue` and read by later callers in the same block is `index-cache`, keyed by `{ timestamp: stacks-block-time, aid: aid }`, populated in `accrue-and-cache` [3](#0-2) . This cache is a deliberate optimization: the accrued index for a given asset at a given block-time is deterministic and independent of which caller triggered the accrual — it depends only on elapsed time and the vault's own rate state, not on borrower identity or attacker-supplied parameters. A caller "priming" this cache for `aid` in block N simply saves the next caller the redundant recomputation of the *same* correct index; it does not let an attacker inject a different or manipulated index value. There is no attacker-controlled input to `vault-accrue` itself (it takes no manipulable argument beyond the registry-derived `aid`), so there is no path by which A's transaction causes B's `liquidate` (where the "collateral == debt × penalty" invariant is actually enforced, not in `repay`) to compute an incorrect or inflated collateral seizure.

Because (1) the routing target is constrained to the DAO-registered asset set rather than attacker-chosen, (2) the shared cache stores a time-deterministic, caller-independent value, and (3) the cited invariant belongs to `liquidate`'s logic rather than `repay`/`vault-accrue`, there is no demonstrable divergence between B's outcome with and without A's prior `repay` call. This does not meet the required two-account, distinct-victim defect bar.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L189-196)
```text
(define-private (vault-accrue (aid uint))
  (if (is-eq aid STX) (contract-call? .v0-vault-stx accrue)
  (if (is-eq aid sBTC) (contract-call? .v0-vault-sbtc accrue)
  (if (is-eq aid stSTX) (contract-call? .v0-vault-ststx accrue)
  (if (is-eq aid USDC) (contract-call? .v0-vault-usdc accrue)
  (if (is-eq aid USDH) (contract-call? .v0-vault-usdh accrue)
  (if (is-eq aid stSTXbtc) (contract-call? .v0-vault-ststxbtc accrue)
  ERR-UNKNOWN-VAULT)))))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L245-257)
```text
(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid })
        (cached? (map-get? index-cache cache-key)))

    (match cached?
      ;; cache HIT: return cached value (1 read only)
      cached-indexes (ok cached-indexes)

      ;; cache MISS: accrue and cache (vault-accrue now returns indexes)
      (let ((indexes (try! (vault-accrue aid))))
        ;; store in cache
        (map-set index-cache cache-key indexes)
        (ok indexes)))))
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1316-1319)
```text
(define-public (repay (ft <ft-trait>) (amount uint) (on-behalf-of (optional principal)))
  (let ((address (contract-of ft))
        (asset (try! (get-asset address)))
        (asset-id (get id asset))
```
