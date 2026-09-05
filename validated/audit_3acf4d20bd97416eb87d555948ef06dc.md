### Title
Double-counting of L1 Bitcoin lockup outputs via `verify-l1-lockups` in `pox-5.clar` due to per-call-only outpoint deduplication - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-l1-lockups` / `validate-l1-lockup` in `pox-5.clar` validate a set of Bitcoin L1 lockup proofs (SPV headers + Merkle proofs) submitted by a staker and sum the locked sats into `sum`. Duplicate detection for a given Bitcoin output (`txid`/`output-index`) is only tracked in a `seen-outpoints` accumulator that is initialized fresh to `(list)` at the start of each call and is never persisted to contract storage. This is directly analogous to the reported `SVFHook.addLiquidity` bug class: a user-supplied artifact (there, a pool key; here, an L1 lockup proof/outpoint) is accepted and used to credit value without validating it against the canonical, already-consumed state of the system, letting an attacker reuse the same real resource to be credited multiple times.

### Finding Description
`verify-l1-lockups` seeds the fold's accumulator with an empty `seen-outpoints: (list)` on every invocation: [1](#0-0) 

`validate-l1-lockup` then checks for duplicates only against this same-call accumulator via `(is-none (index-of? seen-outpoints outpoint))`, and appends the outpoint to it, before adding `(get amount output)` to `sum`: [2](#0-1) 

The comment on `verify-l1-lockups` explicitly documents this scope limitation: "`seen-outpoints` tracks every (txid, output-index) pair already credited **in this call**": [3](#0-2) 

I searched the contract for any persistent map that records previously-consumed outpoints across calls (e.g. `used-outpoints`, `outpoint-used`, `credited-outpoints`, `lockup-outpoint`) and found none outside this same file's local, in-call usage. If no such global tracking exists elsewhere in the registration/rollover flow that calls `verify-l1-lockups` (e.g. `register-for-bond`), then the same valid Bitcoin lockup transaction/output can be submitted again in a subsequent call (a new `register-for-bond`/rollover transaction) and be credited a second time, since each call starts `seen-outpoints` from empty.

This breaks the equality that `sum of sats credited to stakers/bonds` must equal `sats actually locked once on Bitcoin` — the same physical BTC lockup could be counted multiple times, analogous to the reported issue where a user-supplied key/proof was not checked against the canonical already-tracked state.

### Impact Explanation
If the same L1 lockup output can be re-submitted across separate calls to credit sats again, an attacker/staker could inflate their credited/staked sats without locking additional BTC, resulting in unbacked stacking weight/rewards being attributed to a bond or staker for sats that were only locked once — a double-counting of a commitment. Per the given severity mapping this corresponds to Critical impact ("double-counting a commitment or reward").

### Likelihood Explanation
This requires no privileged role — any staker able to call the public registration/rollover function that invokes `verify-l1-lockups` could attempt to resubmit a previously-used lockup proof in a new transaction. Likelihood is high if, as the in-call-only accumulator and its own documentation suggest, there is no cross-call persistent state guarding against outpoint reuse.

### Recommendation
Persist consumed outpoints (or the corresponding bond/staker credit) in contract storage (e.g., a `(define-map used-l1-outpoints { txid: (buff 32), output-index: uint } bool)`), and check/set this map inside `validate-l1-lockup` in addition to (or instead of) the ephemeral `seen-outpoints` accumulator, so that a given Bitcoin lockup output can only ever be credited once across the lifetime of the contract, not just once per call.

### Proof of Concept
Conceptual PoC (exact calling function not fully confirmed due to search/iteration limits):
1. Staker submits a valid L1 lockup proof (header, Merkle proof, output) via the public function that calls `verify-l1-lockups` (e.g. `register-for-bond`), successfully being credited `amount` sats.
2. Staker submits a second transaction (a new call) containing the exact same lockup `output` (same `tx`/`output-index`) in the `outputs` list.
3. Because `seen-outpoints` is reinitialized to `(list)` on each call (`stackslib/src/chainstate/stacks/boot/pox-5.clar:2013`), the duplicate check in `validate-l1-lockup` (`stackslib/src/chainstate/stacks/boot/pox-5.clar:2086-2088`) does not detect that this outpoint was already credited in the prior call, and the same sats are counted/credited again.

Note: I was unable to fully trace the exact public entry point (`register-for-bond`) and confirm whether any *other* layer (outside `verify-l1-lockups`) prevents this reuse, due to tool iteration limits. This should be verified directly against `register-for-bond` and any related bond-registration logic in `pox-5.clar` before treating this as fully confirmed.

### Citations

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2027-2030)
```text
;; - `sum` is the running total of sats from all valid lockups processed so far.
;; - `seen-outpoints` tracks every (txid, output-index) pair already credited
;;   in this call. Duplicate entries is rejected via
;;   ERR_DUPLICATE_LOCKUP_OUTPOINT.
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2066-2113)
```text
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
            )
            ERR_INVALID_MERKLE_PROOF
        )
        (ok {
            staker: (get staker accumulator),
            minimum-unlock-height: (get minimum-unlock-height accumulator),
            staker-unlock-bytes: (get staker-unlock-bytes accumulator),
            early-unlock-bytes: (get early-unlock-bytes accumulator),
            sum: (+ (get sum accumulator) (get amount output)),
            seen-outpoints: (unwrap-panic (as-max-len? (append seen-outpoints outpoint) u10)),
        })
    )
)
```
