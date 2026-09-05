Based on my research, I found a strong analog to the reported bug class in `pox-5.clar`'s L1 Bitcoin-lockup verification logic. I was unable to fully confirm (due to tool-call budget) whether a persistent, cross-transaction outpoint registry exists elsewhere in the ~3000-line `pox-5.clar` file that would prevent replay of the same Bitcoin lockup output across separate calls — this is explicitly noted as an open uncertainty below.

### Title
Same-call-only duplicate-outpoint check in `verify-l1-lockups` may allow a single Bitcoin lockup to be credited as sats multiple times across separate registrations - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-l1-lockups` / `validate-l1-lockup` in `pox-5.clar` compute the sats-value of a staker's L1 (Bitcoin) timelock outputs and use that computed `sum` to credit an sBTC-equivalent bond/stake position. Duplicate-detection (`seen-outpoints`) is initialized fresh on every call and only guards against the same outpoint appearing twice *within a single* list of up to 10 outputs passed in that call, exactly the same class of "trust the caller-supplied amount without a cross-call sufficiency check" flaw described in the external report (there the router trusted `assetDifference` without slippage-bounding it against the user's committed `amount`; here the contract computes a `sum` from proofs but the code path shown does not persist which outpoints were already counted across calls).

### Finding Description
`verify-l1-lockups` builds its accumulator as: [1](#0-0) 
with `seen-outpoints: (list)` freshly initialized every time the function runs. `validate-l1-lockup`'s fold step only asserts `(is-none (index-of? seen-outpoints outpoint))` against this same-call list: [2](#0-1) 
and returns `(ok (get sum accumulation))`, a sats total that downstream code (e.g. bond registration / `roll-sbtc`) uses to credit sBTC-equivalent value: [3](#0-2) 

Because the duplicate check is scoped to the current call's `(list 10 ...)` argument rather than to a durable, contract-level record of previously-credited `(txid, output-index)` pairs, the same on-chain Bitcoin lockup transaction/output could in principle be submitted again in a later, separate call (e.g. a new bond registration, or a stake update) and be re-summed into `sum`, crediting sats value for a lockup that was already counted once. This breaks the equality that "sats credited via an L1 proof == sats actually and newly locked on Bitcoin for this staker," analogous to the reported bug where the router trusted a computed amount (`assetDifference`) without validating it against the amount actually promised/committed.

### Impact Explanation
If the same Bitcoin lockup output can be re-presented across separate registrations, a staker could double-count (or n-times count) a single BTC-locked amount toward multiple bond positions or increase a stake beyond what is actually backed by Bitcoin-locked sats. This falls under the "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment" category, which the task rules classify as **Critical**.

### Likelihood Explanation
Likelihood is uncertain and NOT fully confirmed: I could not verify within the available tool budget whether `pox-5.clar` maintains a persistent map (e.g., a `used-l1-outpoints` style map) elsewhere in the file that is checked/updated outside of `verify-l1-lockups`'s local fold, which would neutralize this issue. The code sections I did read show only a call-local, list-based duplicate check, and the accompanying doc comment explicitly says seen-outpoints tracks pairs "already credited **in this call**" — wording that itself suggests cross-call replay is not addressed at this layer. Without confirming the calling context (e.g. whether `register-sbtc-bond`/bond-registration functions independently deduct/track spent Bitcoin UTXOs), the exploitability of this path cannot be stated with full confidence.

### Recommendation
Add a persistent, contract-level map keyed by `(txid, output-index)` that is checked and updated by `validate-l1-lockup` (or by its caller) before any sats are added to `sum`/credited to a bond or stake, so that no Bitcoin lockup output can ever be counted more than once across the lifetime of the contract, not just within a single call's input list.

### Proof of Concept
Not fully constructible without confirming whether a cross-call outpoint registry exists elsewhere in `pox-5.clar`; this would require tracing every caller of `verify-l1-lockups` (e.g., bond registration and any stake-update paths) to confirm whether spent outpoints are recorded persistently. This should be verified with full repository access (e.g., a Devin session) before treating this as confirmed rather than a plausible analog.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1938-1979)
```text
;; Move a staker's custodied sBTC from `old-sbtc` to `new-sbtc`, transferring
;; only the net difference: pull the increase from the staker, or refund the
;; decrease. `total-sbtc-staked` is updated by the net change. A registration
;; with no rollover passes `old-sbtc` of `u0`, which transfers the full amount.
;; A no-op when the two are equal.
(define-private (roll-sbtc
        (staker principal)
        (old-sbtc uint)
        (new-sbtc uint)
    )
    (begin
        (if (> new-sbtc old-sbtc)
            (let ((delta (- new-sbtc old-sbtc)))
                (try! (contract-call?
                    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                    transfer delta tx-sender current-contract none
                ))
                (var-set total-sbtc-staked (+ (var-get total-sbtc-staked) delta))
            )
            (if (< new-sbtc old-sbtc)
                (let ((delta (- old-sbtc new-sbtc)))
                    (try! (as-contract?
                        ((with-ft
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                            "sbtc-token" delta
                        ))
                        (try! (contract-call?
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                            transfer delta tx-sender staker none
                        ))
                    ))
                    (var-set total-sbtc-staked
                        (- (var-get total-sbtc-staked) delta)
                    )
                )
                ;; new-sbtc == old-sbtc, no transfer needed
                true
            )
        )
        (ok true)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2004-2019)
```text
    (let (
            (bond (unwrap! (get-protocol-bond bond-index) ERR_BOND_NOT_FOUND))
            (accumulation (try! (fold validate-l1-lockup (get outputs lockups)
                (ok {
                    sum: u0,
                    staker: staker,
                    minimum-unlock-height: (get-bond-l1-unlock-height bond-index),
                    staker-unlock-bytes: (get staker-unlock-bytes lockups),
                    early-unlock-bytes: (get early-unlock-bytes bond),
                    seen-outpoints: (list),
                })
            )))
        )
        (ok (get sum accumulation))
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2084-2088)
```text
            ERR_INVALID_LOCKUP_AMOUNT
        )
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```
