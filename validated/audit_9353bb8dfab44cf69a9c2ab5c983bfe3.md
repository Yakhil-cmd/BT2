## Analysis

The external report's bug class — insufficient validation of a list argument that allows duplicate/replayed entries in an unauthenticated, financially consequential function — maps to `register-for-bond` in `pox-5.clar`, specifically its L1 Bitcoin-lockup proof verification path.

`register-for-bond` accepts a `btc-lockup` argument that, on the L1 path, is a list of Bitcoin-transaction inclusion proofs (`outputs`), each attesting that a specific BTC UTXO was locked to the staker via a timelock script [1](#0-0) . The sats credited to the staker's bond come from `verify-l1-lockups`, which folds `validate-l1-lockup` over the `outputs` list, using a **transient, per-call** `seen-outpoints` accumulator that starts as `(list)` on every invocation: [2](#0-1) 

`validate-l1-lockup` rejects an outpoint if it already appears in `seen-outpoints` for *this* fold, via `ERR_DUPLICATE_LOCKUP_OUTPOINT`: [3](#0-2) 

This is confirmed by the integration test comment, which explicitly states the dedup is scoped to a single `register-for-bond` call ("the per-output dedup inside `validate-l1-lockup` trips before the post-fold sum check") [4](#0-3) .

Critically, there is **no persistent, contract-state map of already-consumed Bitcoin outpoints** across separate `register-for-bond` calls (unlike a typical UTXO/nullifier design). The `seen-outpoints` list lives only inside the `fold`'s accumulator tuple and is discarded after the call returns. The staker's `protocol-bond-memberships` record produced from this credits `sats-total` and drives `protocol-bonds-total-staked`, signer-cycle share accounting, and reward computation: [5](#0-4) .

If a staker's bond membership is later cleared (bond matures, rolls over, or is exited) while the underlying Bitcoin timelock output remains unspent and its `unlock-burn-height` still satisfies a later bond's minimum-unlock requirement, the same physical BTC lockup proof (`tx`, `output-index`, `header`, merkle proof) can be resubmitted in a subsequent `register-for-bond` call for a new bond period. Because `seen-outpoints` resets to empty at the start of every call, the second submission passes the duplicate check and the same locked BTC is credited a second time as `sats-total`, inflating `protocol-bonds-total-staked`, signer cycle shares, and ultimately reward-share weighting — without any additional STX or Bitcoin ever having been locked.

I was not able to fully confirm, from the indexed snippets alone, whether `existing-membership`/allowance bookkeeping around lines 679–719 of `pox-5.clar` incidentally blocks *all* forms of this replay (e.g., across bond rollovers or after voluntary exit) — this needs to be verified directly against the full function body and the `ERR_ALREADY_REGISTERED` gate mentioned in the test suite, since the indexed excerpts only show partial control flow.

### Title
Cross-call replay of L1 Bitcoin lockup proofs in `register-for-bond` double-counts locked sats - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-l1-lockups`/`validate-l1-lockup` only deduplicate lockup outpoints *within a single* `register-for-bond` call via a transient `seen-outpoints` list that is reset every call. No persistent on-chain record of previously-credited Bitcoin outpoints exists, so the same BTC lockup proof can potentially be resubmitted across separate `register-for-bond` calls (e.g., after a bond rolls over or the staker exits and re-registers for a new bond) to credit `sats-total` more than once for the same physical BTC lock.

### Finding Description
`register-for-bond` computes `sats-total` from `verify-l1-lockups`, whose fold accumulator initializes `seen-outpoints: (list)` fresh on every call [2](#0-1) . `validate-l1-lockup` checks `(is-none (index-of? seen-outpoints outpoint))` only against this fresh, call-scoped list [6](#0-5) . The resulting `sats-total` is written into `protocol-bond-memberships` and added to `protocol-bonds-total-staked` for the new bond [5](#0-4) . There is no `used-l1-outpoints` (or similar) map checked/updated across calls, so a staker whose bond membership becomes eligible to re-register (rollover, early exit, or natural bond-end) can resubmit the identical Bitcoin proof for a new bond, crediting sats a second time while only one Bitcoin UTXO was ever actually locked.

### Impact Explanation
This double-counts a Bitcoin commitment: `protocol-bonds-total-staked` and signer-cycle share totals become inflated relative to the STX/BTC genuinely locked, which can proportionally overstate the staker's/signer's share of sBTC rewards or reward slots computed from `sats-total`. Per the given severity mapping, double-counting a commitment used in reward distribution is Critical.

### Likelihood Explanation
Exploiting this requires the attacker to control a real Bitcoin timelock output whose `unlock-burn-height` conservatively exceeds the minimum required by more than one bond period, and requires that the contract-side gating (`ERR_ALREADY_REGISTERED`, existing-membership checks) does not incidentally prevent re-registration in every rollover/exit scenario. Whether such a gap actually exists end-to-end could not be fully confirmed from the available excerpts of `register-for-bond`'s full body and would need direct code review/testing to establish definitively.

### Recommendation
Persist consumed L1 outpoints (e.g., a `used-l1-lockup-outpoints` map keyed by `{txid, output-index}`) that is checked and updated across *all* `register-for-bond` calls, not just within a single call's fold, so a given Bitcoin lockup output can only ever be credited to one active bond membership.

### Proof of Concept
Conceptual (not fully verified against complete contract control flow):
1. Staker locks BTC output `O` via the canonical P2WSH timelock script for `staker`, with `unlock-burn-height` set beyond the requirements of two consecutive bond periods.
2. Staker calls `register-for-bond(bond-index=0, ..., btc-lockup=ok({outputs:[O], ...}))`; `sats-total` is credited to bond 0's membership and totals.
3. Bond 0 matures/rolls over or the staker exits, clearing `protocol-bond-memberships` for the staker.
4. Staker calls `register-for-bond(bond-index=1, ..., btc-lockup=ok({outputs:[O], ...}))` reusing the same Bitcoin proof for `O`; because `seen-outpoints` only tracks duplicates within the current call, this proof passes validation again, crediting `sats-total` to bond 1 as well — double-counting the same underlying BTC lock across two bonds.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L636-668)
```text
;; Register for a protocol bond. In order to call this function,
;; the bond must already have been created, and `tx-sender` must
;; be in the allowlist.
;;
;; The caller must either provide sBTC that they want to lockup,
;; or they must provide proof of their L1 BTC lockup.
(define-public (register-for-bond
        (bond-index uint)
        (signer-manager <signer-manager-trait>)
        (amount-ustx uint)
        ;; Their BTC lockup info. If the response is `ok`, then
        ;; this is a list of outputs corresponding to their timelocks.
        ;; If the response is `err`, this is the amount of sBTC (in sats)
        ;; that they want to lock.
        (btc-lockup (response {
            outputs: (list 10
                {
                    height: uint,
                    tx: (buff 100000),
                    output-index: uint,
                    header: (buff 80),
                    leaf-hashes: (list 14 (buff 32)),
                    tx-count: uint,
                    tx-index: uint,
                    amount: uint,
                    unlock-burn-height: uint,
                }
            ),
            staker-unlock-bytes: (buff 683),
        }
            uint
        ))
        (signer-calldata (optional (buff 500)))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-805)
```text
        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
            amount-sats: sats-total,
        })
        (map-set protocol-bonds-total-staked bond-index
            (+ current-total-staked sats-total)
        )
        ;; A roll-over from an ending bond ADDS the new bond's shares but does
        ;; NOT tear down the old bond's per-cycle shares/delegation (unlike
        ;; `update-bond-registration`, which removes then re-adds).
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            BOND_LENGTH_CYCLES sats-total
        ))

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            BOND_LENGTH_CYCLES amount-ustx false
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2004-2018)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2065-2088)
```text
            (output (try! (get-bitcoin-tx-output? (get tx lockup) (get output-index lockup))))
            (reversed-txid (get txid output))
            (txid (reverse-buff32 reversed-txid))
            (outpoint {
                txid: txid,
                output-index: (get output-index lockup),
            })
            (seen-outpoints (get seen-outpoints accumulator))
        )
        (asserts! (>= unlock-burn-height (get minimum-unlock-height accumulator))
            ERR_INVALID_UNLOCK_HEIGHT
        )
        (asserts! (< unlock-burn-height BITCOIN_LOCKTIME_THRESHOLD)
            ERR_INVALID_UNLOCK_HEIGHT
        )
        (asserts! (is-eq (get script output) expected-script-hash)
            ERR_INVALID_LOCKUP_SCRIPT
        )
        (asserts! (is-eq (get amount output) (get amount lockup))
            ERR_INVALID_LOCKUP_AMOUNT
        )
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```

**File:** stacks-node/src/tests/pox_5_integrations.rs (L1416-1420)
```rust
/// Assertions:
/// - submitting the same lockup outpoint three times in the L1 proof list
///   is rejected with `ERR_DUPLICATE_LOCKUP_OUTPOINT` (u46) — the per-output
///   dedup inside `validate-l1-lockup` trips before the post-fold sum check,
///   and the failure leaves the staker with no bond membership and no STX lock
```
