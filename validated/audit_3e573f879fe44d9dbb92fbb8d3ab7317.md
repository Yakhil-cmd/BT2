### Title
Repeatable L1-lockup crediting due to non-persistent outpoint deduplication - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-l1-lockups` / `validate-l1-lockup` in `pox-5.clar` only prevent a Bitcoin lockup outpoint from being counted twice **within a single call** (via the `seen-outpoints` fold accumulator, capped at `(list 10 ...)`). There is no persistent, contract-level map recording which `(txid, output-index)` outpoints have already been credited to a staker/bond across *separate* transactions. This mirrors the airdrop bug class: a per-call/transient check masquerading as a global uniqueness guarantee, allowing the same underlying value (here, sats locked on L1) to be presented and credited again in a later call.

### Finding Description
`validate-l1-lockup` builds up `seen-outpoints` freshly for every invocation of `verify-l1-lockups`, seeded as `(list)` in `verify-l1-lockups`: [1](#0-0) 

The duplicate check `(asserts! (is-none (index-of? seen-outpoints outpoint)) ERR_DUPLICATE_LOCKUP_OUTPOINT)` only guards against the same outpoint appearing twice in the *same* `outputs` list passed in one call: [2](#0-1) 

There is no map such as `used-l1-outpoints` (or similar) that is written to persistently and checked on subsequent, independent calls to the entry point that invokes `verify-l1-lockups`. Consequently a staker can submit the exact same Bitcoin lockup proof (`tx`, `output-index`, merkle proof, header) in a brand-new transaction and have `verify-l1-lockups` return the same `sum` of sats again, because the accumulator that tracks "already seen" outpoints does not survive between calls — exactly analogous to the airdrop contract's `airdrop[msg.sender]` struct being reset to fresh values after `amount` hits `0`, letting the same claim be replayed.

The credited `sum` (in sats) feeds into signer/staker share bookkeeping (`total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, `staker-shares-staked-for-cycle`) and sBTC custody accounting via `roll-sbtc`: [3](#0-2) 

If the same L1 lockup output can be re-validated and re-summed in a later transaction without a persistent per-outpoint ledger, the staker's credited stake/sBTC allocation can be inflated relative to what was actually locked once on Bitcoin — breaking the equality "sats credited == sats actually locked on Bitcoin."

### Impact Explanation
This breaks the invariant that sats credited by an L1 proof must correspond 1:1 to sats actually locked on Bitcoin. Re-presenting the same lockup outpoint across multiple calls double-counts a commitment, inflating a staker's/signer's recorded stake or sBTC credit without any additional STX/BTC being locked — this falls under "double-counting a commitment or reward," a Critical-tier impact per the rules if it results in unbacked stake weight or sBTC crediting.

### Likelihood Explanation
Likelihood depends on whether the *caller* of `verify-l1-lockups` (the public entry point, not shown in the reviewed excerpt) independently persists processed outpoints elsewhere in the contract. Within the code reviewed, `verify-l1-lockups`/`validate-l1-lockup` themselves provide no such persistence — the deduplication is purely local to the fold. Without confirming a persistent outpoint registry in the calling function, this is a plausible and easily triggerable path since it only requires resubmitting a previously-used, valid Bitcoin proof in a fresh transaction.

### Recommendation
Introduce a persistent map (e.g., `(define-map used-l1-outpoints { txid: (buff 32), output-index: uint } bool)`) that is checked and set for every outpoint accepted by `validate-l1-lockup`/`verify-l1-lockups`, and reject any outpoint already marked as used, regardless of which call or transaction it appears in — not just within the current call's fold.

### Proof of Concept
1. Staker submits a valid L1 lockup proof (`tx`, `header`, `leaf-hashes`, `output-index`, `amount`) via the public entry point that calls `verify-l1-lockups`; `sum` is credited to their stake/sBTC bookkeeping.
2. In a later, separate transaction, the staker resubmits the identical lockup proof. Because `seen-outpoints` is re-initialized to `(list)` at the start of the new call, the `ERR_DUPLICATE_LOCKUP_OUTPOINT` check does not fire, and `sum` (the same sats amount) is credited again.
3. Absent a persistent outpoint ledger, the staker's recorded L1-locked amount is now double what was actually locked on Bitcoin.

Note: this finding is based on the reviewed excerpt of `pox-5.clar`; I could not locate/inspect the public entry point that ultimately calls `verify-l1-lockups` within the available index to confirm whether it independently persists processed outpoints elsewhere. If such a persistent check exists at the caller level, this finding would be invalidated — this should be verified directly against the full file.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2086-2088)
```text
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```
