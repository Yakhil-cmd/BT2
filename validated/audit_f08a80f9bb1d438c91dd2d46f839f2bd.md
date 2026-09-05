### Title
Reused L1 BTC lockup proof allows staker to register for multiple bonds without additional BTC ever being locked - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond`'s L1 path validates a Bitcoin lockup solely by proving that a given transaction output, matching the expected timelock script/amount, is included in a Bitcoin block (`validate-l1-lockup` / `verify-l1-lockups`). The contract has no persistent record of which `(txid, output-index)` outpoints have already been consumed to credit a bond — the only dedup (`seen-outpoints`) is scoped to the single list of outputs passed in *one* call. Consequently the same historical BTC lockup proof can be re-submitted across separate `register-for-bond` calls (rollovers), crediting `sats-total` again for a new bond period even though the underlying BTC may have already been withdrawn/swept once the timelock matured.

### Finding Description
`register-for-bond` computes `sats-total` for the L1 branch via `verify-l1-lockups`, which folds over the supplied outputs with `validate-l1-lockup`: [1](#0-0) 

`validate-l1-lockup` checks that the referenced Bitcoin output (i) matches the timelock script derived from the staker/unlock height/unlock-bytes, (ii) matches the recorded amount, (iii) is included via a valid Bitcoin merkle proof, and (iv) is not a duplicate *within the current call's `seen-outpoints` list*: [2](#0-1) 

Crucially, this only proves *historical inclusion* of the transaction in a Bitcoin block — it says nothing about whether the referenced coins are still locked/unspent, and there is no contract-side map recording that a given outpoint has already been used to credit a previous bond registration. `register-for-bond` itself only guards against the *same staker being an active bond/stake member with an overlapping term* (`bond-overlaps-new-position?` / `ERR_ALREADY_REGISTERED`), and permits a legitimate roll-over into a new bond once the prior term ends, gated by `verify-bond-rollover-window`: [3](#0-2) 

Because the merkle-inclusion proof for a given Bitcoin transaction never becomes invalid (a transaction that was once included in a block stays included forever, even after its output has been later spent on the L1 unlock/early-exit script), a staker can present the exact same `(tx, header, output-index, ...)` tuple again in a subsequent `register-for-bond` call for a new bond period, satisfying `validate-l1-lockup` a second time and being credited `sats-total` (and the corresponding STX lock/reward-share allocation) without ever locking any additional BTC.

### Impact Explanation
This breaks the equality the L1 lockup mechanism is supposed to enforce: `sats credited to a bond == sats actually locked in a live, unspent Bitcoin timelock output`. A staker can repeatedly roll their bond membership forward using a single BTC lockup (including one that has already matured and been swept back to the owner), obtaining STX-lock/reward-share credit each time as if fresh BTC collateral had been posted. This is unbacked crediting / double-counting of a Bitcoin-backed commitment, which the rules classify as Critical (double-counting a commitment / crediting sats never actually locked at the time of the second credit).

### Likelihood Explanation
The attack requires only: (1) a staker who has previously completed one legitimate L1 lockup and `register-for-bond` call, and (2) reaching the end of that bond's term (the normal roll-over window checked by `verify-bond-rollover-window`), then calling `register-for-bond` again for the next bond period while re-submitting the original (already-used, possibly already-spent) lockup proof instead of a fresh one. No signer, admin, or oracle collusion is needed — this is fully reachable by an ordinary staker using the standard public entry point.

### Recommendation
Persist a global (not per-call) record of every `(txid, output-index)` outpoint that has ever been credited via `validate-l1-lockup`/`verify-l1-lockups`, and reject any `register-for-bond` call that references an outpoint already present in that record — mirroring the intra-call `seen-outpoints` dedup but scoped across the whole contract lifetime instead of a single call.

### Proof of Concept
1. Staker locks `S` sats into the canonical P2WSH timelock script for bond period `N`, then calls `register-for-bond(N, ..., btc-lockup=(ok {outputs: [proof_A]}))`. This succeeds and credits `sats-total = S`, locking STX accordingly (as exercised by the existing integration test `check_pox_5_register_for_bond_l1_lockup_lifecycle`).
2. Bond `N`'s term ends; the staker sweeps the matured BTC back to themselves via the OP_IF unlock branch of the timelock script (as exercised in the "unlock-sweep" integration test flow).
3. Within `verify-bond-rollover-window`'s allowed window, the staker calls `register-for-bond(N+6, ..., btc-lockup=(ok {outputs: [proof_A]}))` again, re-submitting the *same* `proof_A` (same `tx`, `header`, `output-index`) used in step 1.
4. `validate-l1-lockup` re-verifies the merkle inclusion of the (now already-spent) transaction successfully — since inclusion proofs never expire and there is no global "already credited" outpoint table — and credits `sats-total = S` again for bond `N+6`, even though no new BTC was locked. [4](#0-3)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L764-801)
```text
        ;; Reject if an existing membership *overlaps* this bond. An existing
        ;; bond whose staking term ends no later than this bond's first cycle
        ;; (e.g. rolling from bond N into bond N+6) is allowed.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_REGISTERED
        )

        ;; Settle rewards before updating state
        (settle-rewards signer first-reward-cycle (some bond-index))
        (settle-staker-rewards signer first-reward-cycle (some bond-index)
            tx-sender
        )

        ;; A rollover from a non-overlapping existing bond may only happen in
        ;; that bond's L1 unlock window, the last 1/2 cycle.
        (try! (verify-bond-rollover-window existing-membership))

        ;; Move the staker's custodied sBTC into this bond, transferring only the
        ;; net difference vs. any bond they're rolling over from.
        (try! (roll-sbtc tx-sender old-sbtc new-sbtc))

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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1981-2019)
```text
;; Verify l1 lockup information for a staker. This asserts that each lockup
;; corresponds to the right timelock script for this staker, and that the lockup
;; occurred on-chain. If everything is valid, this returns the sum of all lockups in sats.
(define-private (verify-l1-lockups
        (staker principal)
        (bond-index uint)
        (lockups {
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
        })
    )
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2021-2113)
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
