### Title
L1 BTC lockup outpoints are only deduplicated within a single `register-for-bond` call, allowing the same on-chain lockup to be credited to multiple bonds/stakers - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond` accepts either an sBTC deposit or a list of Bitcoin L1 timelock outputs as proof of locked BTC, via `verify-l1-lockups` → `validate-l1-lockup` [1](#0-0) . `validate-l1-lockup` folds over the caller-supplied `outputs` list, verifying each output's script/amount/merkle proof and tracking `seen-outpoints` to reject *duplicates within that single call* [2](#0-1) . There is no contract-level map that records L1 outpoints already consumed by a *previous* `register-for-bond` call (searched the file for any persistent outpoint-tracking map; none exists). This is structurally the same class of bug as the Balancer report: a batch/aggregate operation (`fold` over a list of "legs", analogous to Balancer's `batchSwap` steps) is trusted to self-report which of its components were already consumed, and the contract only guards against intra-call duplication, not cross-call duplication.

### Finding Description
`verify-l1-lockups` sums the `amount` of every output in the caller-provided `outputs` list via `fold validate-l1-lockup`, seeded with an empty `seen-outpoints` accumulator [3](#0-2) . Inside the fold, `ERR_DUPLICATE_LOCKUP_OUTPOINT` only fires if the outpoint already appears in `seen-outpoints`, which is reset to `(list)` at the start of every call [4](#0-3) [5](#0-4) . There is no persistent map keyed by `(txid, output-index)` that is checked/updated across transactions, so the same Bitcoin lockup output can be supplied again in a later `register-for-bond` call — either by the original staker registering for a second bond, or by any other allow-listed staker who can reconstruct/observe the same merkle proof and header bytes (all of which are public once the BTC transaction is mined).

The resulting `sats-total` from `verify-l1-lockups` is used to: set `amount-sats` in `protocol-bond-memberships`, increase `protocol-bonds-total-staked` [6](#0-5) , and gate the required `amount-ustx` via `min-ustx-for-sats-amount` [7](#0-6) . This equally feeds `add-staker-to-bond-cycles` (bond/reward-share weight) and `add-staker-to-signer-cycles`, i.e., signing weight and reward eligibility. Since the L1 path sets `new-sbtc = u0` (no physical sBTC custody check) [8](#0-7) , `sats-total` from a reused proof directly inflates `protocol-bonds-total-staked` and staked shares without any additional BTC ever being locked. This breaks the equality "sats credited by an L1 proof == sats actually locked on Bitcoin," because a single BTC lockup can back sats-credits for more than one bond/staker.

### Impact Explanation
This is a Critical-class issue under the given rubric ("sats credited by an L1 proof that were never locked on Bitcoin," "double-counting a commitment or reward"): a single, real BTC timelock output can be used to register multiple bond memberships (same staker rolling into overlapping/multiple bonds across time, or colluding/observing stakers reusing the public proof data), each of which independently increases `protocol-bonds-total-staked`, per-cycle staked shares, and signer voting/reward weight — all without a matching increase in actual locked BTC. This inflates reward-cycle stake totals and signer weight beyond what is actually collateralized, and can be used to farm additional bond slots/rewards from a single locked BTC amount.

### Likelihood Explanation
The BTC lockup output's script, amount, merkle proof, and header are all public once broadcast/mined, so any allow-listed staker (or the original staker across separate bond registrations) can resubmit the identical `outputs` tuple in a fresh `register-for-bond` transaction. The only checks performed (`asserts!` on unlock height, script hash, amount, merkle/header validity, intra-call dedup) all pass again on replay because they do not consult any persisted "already used" record. No admin, miner, or other-user key is required — an ordinary allow-listed staker (or a second allow-listed staker who copies the public proof) can trigger this on their own.

### Recommendation
Persist consumed L1 outpoints in a durable map (e.g., `(define-map used-l1-lockup-outpoints { txid: (buff 32), output-index: uint } bool)`), and have `validate-l1-lockup` check/insert into this map (via `map-insert`, asserting success) instead of relying solely on the call-scoped `seen-outpoints` list, so that a given Bitcoin lockup output can only ever be credited once across the contract's lifetime.

### Proof of Concept
1. Staker A locks `X` sats into the canonical timelock P2WSH script for bond `B0`, producing a real Bitcoin transaction, header, and merkle proof.
2. Staker A calls `register-for-bond(bond-index=B0, ..., btc-lockup=(ok {outputs: [that output], ...}))`. `validate-l1-lockup` verifies the proof and credits `sats-total = X` toward `protocol-bonds-total-staked` for `B0`.
3. Before/without spending the BTC UTXO, Staker A (or any other allow-listed staker who can read the same header/merkle-proof bytes) calls `register-for-bond` again for a different bond index `B1` (or, once eligible via `verify-bond-rollover-window`, rolls again), submitting the exact same `outputs` tuple.
4. `validate-l1-lockup`'s `seen-outpoints` check is reinitialized to `(list)` for this new call, so the duplicate check does not trip; the proof re-verifies successfully and `sats-total = X` is credited again, this time toward `B1`'s `protocol-bonds-total-staked` and the staker's/second staker's bond shares — with only one `X`-sat BTC lockup ever having occurred on-chain.

Note: I was not able to fully trace every call site that consumes `protocol-bonds-total-staked`/per-cycle shares to quantify the exact downstream reward/signing-weight impact within the available index; a Devin session with full repo access would be needed to confirm end-to-end reward payout consequences and to implement/verify the fix (e.g., via the existing `pox-5` unit/integration test harness).

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L642-676)
```text
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
    )
    (let (
            (signer (contract-of signer-manager))
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L683-687)
```text
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L712-719)
```text
        ;; Verify that they're sending enough STX
        (asserts!
            (>= amount-ustx
                (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
                    (get min-ustx-ratio bond)
                ))
            ERR_INSUFFICIENT_STX
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-801)
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
