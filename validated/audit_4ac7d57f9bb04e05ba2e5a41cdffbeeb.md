### Title
Stale within-block index cache lets a caller consume a favorable liquidity/borrow index that a same-block liquidation already wrote down - (File: mainnet/contracts/market/v0-4-market.clar)

### Summary
### Finding Description
`market.clar` caches vault liquidity/borrow indexes per `{timestamp, aid}` so that multiple market operations in the same block avoid repeated cross-contract vault calls: [1](#0-0) 
The cache is only invalidated when `stacks-block-time` changes, i.e. once per block, and is populated by whichever caller first triggers `accrue-and-cache`/`get-cached-indexes` for a given asset in that block: [2](#0-1) 

Separately, when a liquidation leaves a borrower with no collateral and unpaid debt, `market.clar` calls `socialize-debt` on the affected vault, which writes the vault's `lindex` (and `assets`/`total-borrowed`) down directly in vault storage to reflect the loss: [3](#0-2) 
This write-down happens on the vault contract's own state, but it is not what feeds the market's `index-cache-` map for the current block — that map is only refreshed by `accrue-and-cache`, and once a `{timestamp, aid}` entry exists it is returned unconditionally for the rest of the block: [4](#0-3) 
Price resolution for zTokens (`resolve-ztoken`) and any collateral valuation in the same block read this cached `lindex`: [5](#0-4) 

Because the write-down performed by `socialize-debt` is not reflected in the market's per-block cache once it has been primed, any user (attacker or victim) who caused the cache to be primed *before* the socialization occurs, and who performs another market operation (e.g., borrow, withdraw, or health check) *after* the socialization but still within the same block, will have their zToken collateral or vault share valued using the stale, pre-loss index instead of the corrected one.

### Impact Explanation
This is directly analogous to the reported `afiVault` bug: an attacker can transact around a discrete, in-block state transition of the shares-to-assets exchange rate to capture value that should have been distributed at the corrected (lower) rate. Here the "oracle update" analog is the bad-debt write-down (`socialize-debt`), and the shared state is the market's `index-cache-` map, which is primed by one caller and consumed by a different caller (or the same caller in a second call) later in the block — a shared-cache class explicitly in scope. Concretely: an attacker with zToken collateral or an open borrow position can time a market action to occur after a liquidation's `socialize-debt` call but still ride on the stale cached index, over-valuing their collateral for a borrow/withdrawal and extracting more value than their post-loss share, at the expense of the remaining suppliers of that vault who must absorb a larger portion of the socialized bad debt. This lands on the **temporary/permanent freezing or theft of unclaimed yield among suppliers** (the vault's assets pool), since the attacker extracts value the corrected index would have denied them, socializing an outsized loss onto other, unrelated depositors.

### Likelihood Explanation
Requires (a) an in-progress liquidation that will trigger `socialize-debt` visible in the mempool/same block, and (b) the attacker holding a related zToken position or borrow so they can act on the stale cache before/after the write-down within the same block window (`stacks-block-time` granularity). This needs precise ordering within a single block and mempool visibility of the liquidation transaction, so likelihood is moderate — it depends on Stacks block construction/ordering behavior, similar to the mempool front-running assumption in the original report.

### Recommendation
- Invalidate or refresh the market's `index-cache-` entry for an asset whenever `socialize-debt` (or any other vault-state-mutating call) is executed within the same transaction/block, rather than relying purely on the `stacks-block-time` key.
- Alternatively, have `socialize-debt` route through the same `accrue-and-cache` path so the cache is always kept consistent with the latest on-chain vault state within a block.
- Consider re-deriving `lindex`/`index` directly from the vault (bypassing cache) for any market operation that occurs after a liquidation/socialization event in the same block.

### Proof of Concept
1. Block N: Attacker's first transaction (e.g., a small borrow or health check involving zX collateral) causes `accrue-and-cache` to populate `index-cache-{timestamp: T, aid: X}` with the pre-loss `lindex`.
2. Still in block N: A liquidator's transaction resolves a borrower's position with no remaining collateral, triggering `market.clar`'s bad-debt path, which calls `socialize-debt` on vault X, writing `lindex` down in the vault's own storage.
3. Still in block N: Attacker's second transaction (e.g., `borrow` against zX collateral, or a withdrawal) triggers `resolve-ztoken`/`get-cached-indexes` for aid X, which returns the **stale, pre-loss** `lindex` cached in step 1 instead of the corrected value, because the cache key `{timestamp: T, aid: X}` already exists.
4. The attacker's collateral/shares are valued higher than their true post-loss worth, letting them borrow more or withdraw more than their fair post-socialization share, at the expense of other suppliers in vault X.

Note: I could not fully trace the exact liquidation call sequence in `v0-4-market.clar` (specifically whether `accrue-and-cache` for the affected vault is always re-invoked immediately before `socialize-debt-asset` runs, which would close this window) due to index size limits on the codebase snapshot available to this tool. Confirming the precise ordering of `accrue-and-cache` vs. `socialize-debt-asset` calls within the liquidation flow would require a full read of `mainnet/contracts/market/v0-4-market.clar`; a Devin session with full repository access should verify this before treating the finding as confirmed.

### Citations

**File:** docs/market.md (L588-603)
```markdown
;; In market.clar
(define-map index-cache- 
  { timestamp: uint, aid: uint }
  { index: uint, lindex: uint })

(define-read-only (get-cached-indexes (aid uint))
  (map-get? index-cache- { timestamp: stacks-block-time, aid: aid }))

(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid })
        (cached? (map-get? index-cache- cache-key)))
    (match cached?
      existing existing  ;; Return cached if exists
      (let ((fresh (vault-accrue aid)))  ;; Otherwise accrue vault
        (map-set index-cache- cache-key fresh)
        fresh))))
```

**File:** docs/vaults.md (L295-313)
```markdown
## Index Caching in Market

The market contract caches vault indexes per timestamp to avoid redundant vault calls within the same block:

```clarity
;; In market.clar
(define-map index-cache- 
  { timestamp: uint, aid: uint }
  { index: uint, lindex: uint })

(define-private (accrue-and-cache (aid uint))
  (let ((cache-key { timestamp: stacks-block-time, aid: aid }))
    ;; Check cache first, accrue vault if needed
    (match (map-get? index-cache- cache-key)
      existing existing
      (let ((fresh (vault-accrue aid)))
        (map-set index-cache- cache-key fresh)
        fresh))))
```
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

**File:** local-testing/contracts/market/market.clar (L342-349)
```text
;; @staging
;; Mock oracle for testing bad debt socialization
(define-private (call-mock (key (string-ascii 32)))
  (let ((res (unwrap! (contract-call? .mock-oracle get-value key) ERR-ORACLE-MOCK)))
    (ok res)))

(define-private (resolve-mock (ident (buff 32)))
  (let ((key (unwrap-panic (from-consensus-buff? (string-ascii 32) ident)))
```

**File:** local-testing/contracts/market/market.clar (L365-369)
```text
(define-private (resolve-ztoken (p uint) (aid uint))
  (let ((cached (unwrap! (get-cached-indexes aid) ERR-ORACLE-CALLCODE))
        (cached-lindex (get lindex cached))
        (scaled (* p cached-lindex)))
    (ok (div-down scaled INDEX-PRECISION))))
```
