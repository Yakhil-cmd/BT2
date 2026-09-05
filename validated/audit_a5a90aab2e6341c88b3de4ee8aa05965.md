### Title
Bitcoin L1 lockup outpoints can be re-submitted across separate calls to double-count sats credit - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`verify-l1-lockups`/`validate-l1-lockup` in `pox-5.clar` only prevents the same Bitcoin outpoint from being counted twice *within a single call's* `outputs` list. The duplicate-detection accumulator (`seen-outpoints`) is initialized fresh as `(list)` on every invocation and is never checked against, or written into, any persistent contract map. A staker can therefore submit the exact same valid Merkle-proven L1 lockup output in two (or more) separate transactions/calls and have it credited as `sum` sats each time. [1](#0-0) [2](#0-1) 

### Finding Description
`validate-l1-lockup` folds over the `outputs` list, checking each Bitcoin output's script, amount, height bounds and Merkle proof, and rejecting duplicates only via `(index-of? seen-outpoints outpoint)` against the accumulator built up *during that same fold call*: [3](#0-2) 

`verify-l1-lockups` seeds this accumulator with an empty list every time it's invoked: [4](#0-3) 

There is no map (e.g. `used-outpoints` / `used-lockups`) persisted across transactions that records which `(txid, output-index)` pairs have already been credited to a staker's sats total. This means the invariant "each Bitcoin-locked output backs exactly one unit of credited sats in pox-5" is enforced only per-call, not globally. A staker who has a single valid L1 lockup transaction can invoke whatever public entry point calls `verify-l1-lockups` (e.g. `register-for-bond`) more than once, or split the same output across multiple bonds/calls, and have the identical `sats` amount added to their credited total each time — since the proof (Merkle proof + header + script match) is real and will re-verify successfully every time.

This breaks the equality the report's bug-class targets directly: "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment" — the same locked BTC is turned into multiple units of on-chain credited stake/collateral.

### Impact Explanation
This is Critical under the stated impact criteria: double-counting a commitment tied to locked value. If the credited sats total feeds into bond/stake sizing, reward-slot weighting, or signer eligibility, an attacker can inflate their effective stake without locking additional BTC, diluting or stealing rewards from honest stakers, or exceeding legitimate collateral requirements.

### Likelihood Explanation
High likelihood for any staker who already has one valid L1 lockup: no special privileges, admin, miner, or other user's key are required — only re-submission of the same previously-accepted proof data in a new transaction. The check that fails to catch this is purely a design gap (missing cross-call/global replay protection), not a hard-to-reach edge case.

### Recommendation
Persist a global `used-outpoints` map (keyed by `{ txid, output-index }`, or `{ staker, txid, output-index }` if per-staker accounting is intended) that is checked and updated inside `validate-l1-lockup`/`verify-l1-lockups`, rejecting any outpoint that has already been credited in a prior transaction, in addition to the existing intra-call duplicate check.

### Proof of Concept
1. Staker performs a real Bitcoin lockup transaction `T` with output `O` matching the expected timelock script for their bond.
2. Staker calls the pox-5 entry point that invokes `verify-l1-lockups` (e.g. `register-for-bond`), submitting `T`/`O` with a valid Merkle proof; `sum` sats are credited.
3. Staker calls the same or another entry point again, submitting the identical `T`/`O` and Merkle proof. Since `seen-outpoints` starts as `(list)` for this new call, `validate-l1-lockup` re-validates the proof successfully (script, amount, height, and Merkle checks all still pass) and credits `sum` sats a second time.
4. The staker now has 2x sats credited against a single, unchanged Bitcoin lockup, without any additional BTC ever having been locked. [5](#0-4)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1984-2019)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2072-2112)
```text
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
```
