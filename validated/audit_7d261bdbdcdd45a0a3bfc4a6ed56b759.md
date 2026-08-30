### Title
`liquidate-multi` non-atomic batching lets a partially-executed `liquidate()` seize collateral while leaving un-socialized debt permanently orphaned - (File: `mainnet/contracts/market/v0-4-market.clar`)

### Summary
`liquidate-multi` wraps a batch of `liquidate` calls in `(ok (map call-liquidate positions))`, so the outer public function *always* returns `ok` regardless of whether any individual `liquidate` call internally fails. Because `call-liquidate` invokes the sibling `liquidate` function as a plain call (not via a `try!`-propagated `contract-call?`), any state mutations that `liquidate` performs *before* hitting a failing `asserts!`/`unwrap!` are committed anyway, since Clarity only rolls back state when the *outermost* invoked public function of the transaction returns `err`. This is the same bug class as the Seaport `CreateOfferer` report: a caller-controlled "skip" path advances/mutates shared external state even though the logical operation is treated as failed by the immediate caller, leaving one system's bookkeeping permanently desynchronized from another's.

### Finding Description
`liquidate` performs its checks (health, slippage, zero-amount, etc.) via `asserts!` at [1](#0-0) , then executes irreversible state mutations:
1. `vault-system-repay` (pulls repayment, updates vault principal) [2](#0-1) 
2. `debt-remove-scaled` on `.v0-market-vault` (removes borrower's primary debt obligation) [3](#0-2) 
3. `collateral-remove` on `.v0-market-vault` (seizes and *sends* the borrower's remaining collateral to the receiver) [4](#0-3) 

Only *after* these three irreversible transfers does the function compute `no-collateral-left` and, if true, attempt bad-debt socialization for the borrower's remaining debt assets via `fold socialize-debt-asset ...`, followed by a final gating check: [5](#0-4) 

`socialize-debt-asset` itself has an "early return if previous socialization failed" accumulator pattern [6](#0-5) , meaning debt assets processed *before* a failing one are already write-off/removed in the vault, while debt assets *after* the failing one are simply skipped — left fully intact on the borrower's books. If any single asset in that fold fails, `socialization-result.success` is `false` and the top-level `asserts!` in `liquidate` fires, making `liquidate` return `(err ERR-BAD-DEBT-SOCIALIZATION-FAILED)`.

When `liquidate` is called directly, this `err` is the transaction's outermost result, so Clarity rolls back everything (repay, debt-remove, collateral-remove) — safe. But when called through `liquidate-multi`: [7](#0-6) 
`call-liquidate` invokes `liquidate` as a plain in-contract call and simply returns its response value into the `map` result list [8](#0-7) . The outer `liquidate-multi` wraps the whole list in `ok`, so the *transaction as a whole* commits — even though one of its constituent `liquidate` calls "failed." All mutations already performed inside that failed `liquidate` call (collateral seizure, primary debt removal, partial debt socialization for assets processed before the failure point) persist, while the debt asset that triggered the fold failure — and any assets after it in the list — remain fully on the borrower's books, uncollectible, and never socialized into the vault's accounting.

### Impact Explanation
The borrower ends up with zero collateral (already seized and sent to the liquidator/receiver) but with outstanding debt on one or more assets that:
- Can never be repaid (borrower has no collateral, and Clarity `liquidate` requires `coll-final > 0` [9](#0-8) , so this position can never be liquidated again to clean up the remaining debt), and
- Was never written down via `vault-socialize-debt`, so the vault(s) backing that unresolved debt asset continue to count it as outstanding principal that will never be repaid.

This is a permanent, protocol-level accounting break: the affected vault's `total-borrowed`/`principal-scaled` overstates real backing assets forever, inflating the vault share price relative to actual redeemable value and ultimately socializing the loss onto LPs (temporary/permanent freezing of funds for the unresolved vault's depositors, with the caller/liquidator instead walking away with a full collateral seizure they should not have obtained without completing debt write-down). This lands on **High** — temporary/permanent freezing of funds — since the un-socialized debt asset's vault liquidity becomes permanently impaired relative to its recorded obligations, and the borrower's position becomes permanently unliquidatable/unresolvable by protocol logic.

### Likelihood Explanation
Reachability is unprivileged: any address can call `liquidate-multi` with an unhealthy borrower position. The trigger requires the bad-debt-socialization fold to fail for a non-first debt asset — e.g., because that asset's vault has been paused for `socialize-debt`-relevant internal calls, or because of an intermediate arithmetic/edge condition inside `vault-socialize-debt`/`debt-remove-scaled` for that specific asset — while the position simultaneously satisfies `no-collateral-left`. Multi-asset debt positions are an explicit, supported feature of the egroup/bitmask system, so constructing such a position is feasible for any user acting as their own borrower, then having any caller (including themselves) invoke `liquidate-multi` against it. I was not able to fully enumerate every concrete failure trigger for `socialize-debt-asset` at a given asset without simulating the full vault state machine, so the precise minimal repro conditions require live testing; the structural flaw (non-atomic batching via unwrapped `map`) is proven directly from the code.

### Recommendation
`liquidate-multi` must not silently swallow a failed `liquidate` call's partial state. Either:
1. Make `call-liquidate`/`liquidate` transactionally atomic per-position by invoking `liquidate` via `as-contract (contract-call? .v0-4-market liquidate ...)` so Clarity's public-call boundary rolls back that position's mutations on error, or
2. Restructure `liquidate` so *all* fallible operations (including bad-debt socialization for every debt asset) are validated/attempted **before** any irreversible transfer (`vault-system-repay`, `debt-remove-scaled`, `collateral-remove`) is executed, guaranteeing an all-or-nothing outcome per position regardless of how it is invoked.

### Proof of Concept
Structural PoC (code-level, not yet run against a live simnet):
1. Attacker sets up Borrower B with an egroup granting two debt assets: Debt-A (primary target) and Debt-C (secondary), and thin collateral sufficient to make the position liquidatable and to leave `no-collateral-left = true` after seizing collateral for Debt-A's liquidation.
2. Condition the environment so that `socialize-debt-asset` fails specifically when processing Debt-C's entry (e.g., Debt-C's vault temporarily paused for the relevant vault call, or an edge-case zero-liquidity condition causing `unwrap!` in `socialize-debt-asset` to hit `failed-status`) — see fold logic at [6](#0-5) .
3. Attacker calls `liquidate-multi` with a single position `{ borrower: B, collateral-ft: ..., debt-ft: Debt-A-ft, debt-amount: X, min-collateral-expected: Y }`.
4. Inside `liquidate` (invoked via `call-liquidate`): `vault-system-repay`, `debt-remove-scaled` (Debt-A), and `collateral-remove` (all of B's collateral, sent to attacker) execute successfully [10](#0-9) ; the subsequent socialization fold fails on Debt-C, causing the top-level `asserts!` at [11](#0-10)  to fire and `liquidate` to return `(err ERR-BAD-DEBT-SOCIALIZATION-FAILED)`.
5. `liquidate-multi` still returns `(ok (list (err ...)))` [12](#0-11) , so the entire transaction commits: B's collateral is gone, Debt-A is cleared, but Debt-C remains on B's books in `.v0-market-vault` with no corresponding write-down in the Debt-C vault — permanently orphaned since B has no more collateral to trigger a future liquidation.

Note: I could not execute this against the simnet test harness to confirm the exact failure trigger for `socialize-debt-asset`/`vault-socialize-debt`; a Devin session with repository and test-runner access should build a Clarinet/simnet test reproducing step 2 precisely to confirm the observable end state (orphaned Debt-C balance with zero borrower collateral) and quantify the resulting vault insolvency.

### Citations

**File:** mainnet/contracts/market/v0-4-market.clar (L901-925)
```text
                                      asset-id) failed-status)
          acc)
        ))

;; -- Liquidation: batch helper ----------------------------------------------

(define-private (call-liquidate (position { borrower: principal,
                                            collateral-ft: <ft-trait>,
                                            debt-ft: <ft-trait>,
                                            debt-amount: uint,
                                            min-collateral-expected: uint }))
  (liquidate (get borrower position)
             (get collateral-ft position)
             (get debt-ft position)
             (get debt-amount position)
             (get min-collateral-expected position)
             none   ;; collateral-receiver defaults to liquidator
             none)) ;; price-feeds not supported in batch - update prices separately

;; ============================================================================
;; READ-ONLY FUNCTIONS
;; ============================================================================

;; -- Pausability getters ----------------------------------------------------

```

**File:** mainnet/contracts/market/v0-4-market.clar (L1488-1493)
```text
    (asserts! (not (is-liquidation-paused debt-aid)) ERR-LIQUIDATION-PAUSED)
    (asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)
    (asserts! (> debt-amount u0) ERR-AMOUNT-ZERO)
    (asserts! (> debt-to-repay u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (> coll-final u0) ERR-ZERO-LIQUIDATION-AMOUNTS)
    (asserts! (>= coll-final min-collateral-expected) ERR-SLIPPAGE)
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1496-1512)
```text
    (try! (vault-system-repay debt-aid debt-to-repay debt-ft debt-address))

    ;; update obligations and socialize bad debt
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

**File:** mainnet/contracts/market/v0-4-market.clar (L1544-1548)
```text
                    (if (> (len fresh-debt-list) u0) ;; if still has debt
                      (let ((socialization-result (fold socialize-debt-asset 
                                                        fresh-debt-list 
                                                        { borrower: borrower, success: true })))
                        (asserts! (get success socialization-result) ERR-BAD-DEBT-SOCIALIZATION-FAILED)
```

**File:** mainnet/contracts/market/v0-4-market.clar (L1593-1599)
```text
(define-public (liquidate-multi
                (positions (list 64 { borrower: principal,
                                      collateral-ft: <ft-trait>,
                                      debt-ft: <ft-trait>,
                                      debt-amount: uint,
                                      min-collateral-expected: uint })))
  (ok (map call-liquidate positions)))
```
