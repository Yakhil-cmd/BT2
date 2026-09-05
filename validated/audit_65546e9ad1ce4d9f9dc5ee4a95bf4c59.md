### Title
Double-counting of L1 Bitcoin lockup outpoints across separate `pox-5` bond registration calls - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`pox-5.clar`'s L1 lockup validation (`validate-l1-lockup`, folded to build the bond's committed sats total) only guards against a Bitcoin outpoint being counted twice *within a single call* via the transient `seen-outpoints` list carried in the fold accumulator. That list is discarded when the transaction returns; nothing persists which `(txid, output-index)` pairs have already been credited to a bond across separate transactions/calls.

### Finding Description
The fold helper `validate-l1-lockup` builds up a `sum` of sats and a `seen-outpoints` list purely as function-call-local accumulator state: [1](#0-0) 
Duplicate detection is enforced only via `(asserts! (is-none (index-of? seen-outpoints outpoint)) ERR_DUPLICATE_LOCKUP_OUTPOINT)`, checked against the in-memory list constructed during that one call: [2](#0-1) 
Everything else validated in this path (block header, merkle proof, script hash, amount) is a proof about a fixed Bitcoin outpoint, which is immutable once mined — the same outpoint can be presented, with the same valid merkle proof, in any number of separate future `pox-5` transactions. I was unable to locate a persisted map (e.g., `define-map credited-outpoints ...`) anywhere in `pox-5.clar` that records outpoints already credited to a bond/stake across transactions — searches for `credited-outpoints`, `outpoints-credited`, `already-credited`, and `processed-outpoint` returned no matches in the file. If bond sats accounting truly has no cross-call persistence for consumed outpoints, a staker could invoke the bond-registration entry point multiple times, each time re-submitting proof of the *same* previously-locked Bitcoin UTXO, and have its `amount` credited into the sats total again on each call, inflating the sats figure backing a bond without any additional STX/BTC ever being locked.

### Impact Explanation
If outpoints are not tracked persistently, this breaks the invariant that "sats credited by an L1 proof" must correspond one-to-one with sats actually locked on Bitcoin — the same UTXO's value could be double- (or N-times-) counted toward a staker's bond commitment, inflating locked/committed value that was never actually locked. Per the scope's impact classification this is Critical: "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment or reward."

### Likelihood Explanation
Exploitability depends entirely on whether some other component (not visible in the indexed excerpts I could retrieve — possibly a persisted map I could not locate, or a check in the calling public function such as `register-for-bond`) enforces global outpoint uniqueness outside the fold. I could not confirm the body of `register-for-bond`/`update-bond-registration` beyond the private fold helper within the available index, so I cannot be certain whether a persisted, cross-transaction outpoint registry exists elsewhere in the contract.

### Recommendation
Confirm whether `pox-5.clar` maintains a persisted map (e.g., `credited-outpoints` keyed by `{txid, output-index}` or a per-staker/per-bond record) that is checked and updated by `map-set`/`map-get?` on every successful lockup credit, independent of the transient fold `seen-outpoints`. If no such persisted check exists, add one so that once an outpoint's sats have been credited to a bond, any subsequent attempt to re-credit that exact outpoint in a later transaction is rejected with `ERR_DUPLICATE_LOCKUP_OUTPOINT` (or equivalent), regardless of which call or which staker submits it.

### Proof of Concept
Not confirmed as directly exploitable from the retrieved code alone, since the full `register-for-bond`/bond-crediting call path was not fully visible in this session's index. The concrete step to validate is: call the pox-5 bond registration entry point twice from the same or a colluding staker, each time supplying the identical Bitcoin `(header, tx, output-index, leaf-hashes, tx-count, tx-index)` proof for a single already-mined lockup output, and observe whether the bond's committed-sats total increases on both calls (double-credit) or is rejected on the second call by a persisted, cross-call outpoint registry. [3](#0-2) [4](#0-3)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2021-2072)
```text
;; Fold function for validating l1 lockup info
;;
;; - `staker` is the lockup owner committed to the timelock script.
;; - `minimum-unlock-height` is the earliest allowed L1 unlock height.
;; - `staker-unlock-bytes` is the subscript that must unlock every output.
;; - `early-unlock-bytes` is the bond's early-exit subscript.
;; - `sum` is the running total of sats from all valid lockups processed so far.
;; - `seen-outpoints` tracks every (txid, output-index) pair already credited
;;   in this call. Duplicate entries is rejected via
;;   ERR_DUPLICATE_LOCKUP_OUTPOINT.
(define-private (validate-l1-lockup
        (lockup {
            height: uint,
            tx: (buff 100000),
            output-index: uint,
            header: (buff 80),
            leaf-hashes: (list 14 (buff 32)),
            tx-count: uint,
            tx-index: uint,
            amount: uint,
            unlock-burn-height: uint,
        })
        (accumulator-res (response {
            staker: principal,
            minimum-unlock-height: uint,
            staker-unlock-bytes: (buff 683),
            early-unlock-bytes: (buff 683),
            sum: uint,
            seen-outpoints: (list 10 {
                txid: (buff 32),
                output-index: uint,
            }),
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (block (try! (parse-block-header (get header lockup))))
            (unlock-burn-height (get unlock-burn-height lockup))
            (expected-script-hash (try! (construct-lockup-output-script (get staker accumulator)
                unlock-burn-height (get staker-unlock-bytes accumulator)
                (get early-unlock-bytes accumulator)
            )))
            (output (try! (get-bitcoin-tx-output? (get tx lockup) (get output-index lockup))))
            (reversed-txid (get txid output))
            (txid (reverse-buff32 reversed-txid))
            (outpoint {
                txid: txid,
                output-index: (get output-index lockup),
            })
            (seen-outpoints (get seen-outpoints accumulator))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2073-2100)
```text
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
        (asserts! (verify-block-header (get header lockup) (get height lockup))
            ERR_INVALID_BTC_HEADER
        )
        ;; verify merkle proof
        (asserts!
            (or
                (is-eq (get merkle-root block) txid) ;; true, if the transaction is the only transaction
                (verify-merkle-proof reversed-txid
                    (reverse-buff32 (get merkle-root block))
                    (get tx-index lockup) (get tx-count lockup)
                    (get leaf-hashes lockup)
                )
```
