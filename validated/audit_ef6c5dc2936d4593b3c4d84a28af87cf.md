### Title
Reused Bitcoin L1 lockup outpoint can be credited to sBTC-bond shares more than once - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`pox-5.clar`'s L1-lockup verification path (`verify-l1-lockups` / `validate-l1-lockup`) proves that a Bitcoin UTXO is a genuine, on-chain timelock output for a given staker, but the anti-replay protection it implements (`seen-outpoints`) is scoped only to the single call's fold accumulator, not persisted globally. This is structurally the same bug class as the AllbridgeCCTP report: a value-crediting function accepts an externally-verifiable proof (there, a Circle attestation; here, a Bitcoin merkle/header proof) and credits an amount from it without checking whether that exact same underlying value has already been credited in a prior call.

### Finding Description
`validate-l1-lockup` ( [1](#0-0) ) validates, for each supplied L1 output: the unlock height, the P2*SH script hash against `construct-lockup-output-script` for `staker`, the BTC block header, and the merkle inclusion proof of the transaction. It also maintains a `seen-outpoints` list to reject duplicate `(txid, output-index)` pairs, but this list is initialized fresh inside `verify-l1-lockups` for every invocation [2](#0-1)  and is never checked against, or persisted into, contract-level state.

Because the dedup set is local to one call, nothing stops a staker from invoking the bond-registration flow (which calls `verify-l1-lockups` and then `roll-sbtc` to move the staker's "custodied sBTC" from `old-sbtc` to `new-sbtc`) a second time — for a different `bond-index`, or after a state reset — supplying the exact same Bitcoin outpoint(s) that were already used to justify a prior credit [3](#0-2) . Since `roll-sbtc` only compares the newly-computed `new-sbtc` sum against the *currently stored* `old-sbtc` for that particular staker/bond-index pairing, reusing the same real UTXO as the basis for a fresh `old-sbtc = 0` baseline (e.g., a new bond) yields another full `delta` credit of “custodied sBTC” shares and stake weight — for BTC that was locked (and already counted) only once.

This breaks the equality that each sat of Bitcoin locked in a timelock output should back at most one unit of protocol-bond share/stake weight; the same physical L1 lockup can back two or more.

### Impact Explanation
This falls under the Critical category "double-counting a commitment or reward": a single Bitcoin lockup UTXO can be used to justify staking shares/signing weight in more than one bond position, inflating a staker's claim on sBTC rewards or governance/signing weight without any additional value being locked on Bitcoin.

### Likelihood Explanation
The only barrier to reuse is that `seen-outpoints` dedups within a single call — an attacker fully controls the `lockups` argument across separate transactions and controls which `bond-index` they register against, so replaying the same BTC proof data across calls requires no privileged access, no signer key, and no timing race; it is a straightforward unprivileged transaction sequence.

### Recommendation
Persist a global (contract-level) map of consumed L1 outpoints (`txid`, `output-index`) keyed independently of `bond-index`/call, and have `validate-l1-lockup` (or its caller) assert that an outpoint has not previously been consumed by any prior successful registration before crediting `sum`, marking it consumed as part of the same transaction.

### Proof of Concept
Not independently executable from static review alone — I was not able to locate and fully trace the public entry point (`register-for-bond`) that consumes `verify-l1-lockups`'s output within the time available, so I cannot confirm with certainty how `old-sbtc`/`new-sbtc` are keyed across bonds versus a single global staker balance. The finding is based on: (1) the explicit code comment describing `roll-sbtc` as supporting "bond → bond ... stake → bond ... bond → stake" rollovers implying multiple bond registrations reference the same staker, and (2) the demonstrable fact that `seen-outpoints` is a fold-local accumulator with no persistent map in the reviewed portion of `pox-5.clar`. Confirming full exploitability requires reading `register-for-bond` and the `staker-shares-staked-for-cycle`/`total-sbtc-staked` update paths in full, which is recommended before treating this as fully validated.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2031-2113)
```text
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
