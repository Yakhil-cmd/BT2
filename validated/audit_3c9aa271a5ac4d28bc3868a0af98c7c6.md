### Title
`verify-l1-lockups`/`validate-l1-lockup` only deduplicate Bitcoin lockup outpoints within a single call, allowing the same L1 lockup to be reused across multiple `register-for-bond`/rollover calls - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`pox-5.clar`'s L1-lockup verification path (`verify-l1-lockups` and its fold helper `validate-l1-lockup`) proves that a Bitcoin UTXO exists, matches the staker's timelock script, and has not been double-counted — but only *within the list of outputs supplied in that single call*. There is no contract-level (persisted) map recording which `(txid, output-index)` outpoints have already been credited to a bond in a prior transaction.

### Finding Description
`verify-l1-lockups` seeds the fold accumulator with an empty `seen-outpoints` list every time it is invoked: [1](#0-0) 

`validate-l1-lockup` checks each output's outpoint against that same in-call `seen-outpoints` accumulator to reject duplicates within the batch, but never checks against any durable data structure that would remember outpoints consumed by earlier, separate calls: [2](#0-1) 

A grep across `pox-5.clar` for a persisted outpoint/lockup map (analogous to `seen-outpoints`) returns no results — the only `define-map` referencing lockups exists in the unrelated `lockup.clar` file, confirming pox-5 keeps no global registry of which Bitcoin outputs have already been credited as bond collateral.

Because the merkle-proof/header verification (`verify-block-header`, `verify-merkle-proof`, `get-bitcoin-tx-output?`) only proves that a given Bitcoin transaction output *exists* and matches the expected timelock script — it says nothing about whether that same output was already used to back a previous `register-for-bond` (or `update-bond-registration`/rollover) call. A staker can therefore resubmit the identical `header`/`tx`/`output-index` proof for the same on-chain lockup in a subsequent bond-registration transaction, and `validate-l1-lockup` will accept it again because its `seen-outpoints` list starts fresh each call.

### Impact Explanation
This breaks the equality "sats credited to `protocol-bonds-total-staked` / `total-sbtc-staked` == sats actually locked on Bitcoin." A single Bitcoin lockup UTXO can be credited as collateral to more than one bond/registration, inflating a staker's or the protocol's accounted sBTC-bond stake without a corresponding new BTC lock — a double-count of an L1 commitment, matching the Critical-tier criterion "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment."

### Likelihood Explanation
The staker fully controls the inputs to `verify-l1-lockups` (the `header`, `tx`, `leaf-hashes`, etc. are all caller-supplied) and can simply resubmit a previously-used, still-valid proof in a new call; no privileged role or victim key is required. The precondition is only that `register-for-bond`/rollover can be invoked more than once (e.g., across different bonds, or after unstaking and re-registering) with an L1 proof from an already-spent-for-collateral output.

### Recommendation
Persist consumed L1 lockup outpoints in a contract `define-map` (e.g., `used-l1-outpoints { txid, output-index } -> bool`) that is checked and updated by `validate-l1-lockup` across all calls, not just within a single fold, so the same Bitcoin output can never back more than one bond credit.

### Proof of Concept
1. Staker locks BTC in a valid timelock output and calls `register-for-bond` with a `lockups` proof referencing that output; `verify-l1-lockups` credits `amount` sats to the bond.
2. The same staker (or via `update-bond-registration`/a second bond) calls `register-for-bond` again, submitting the identical `header`/`tx`/`output-index` proof.
3. Because `seen-outpoints` is re-initialized to `(list)` for this new call and there is no persisted map of previously-consumed outpoints, `validate-l1-lockup` passes and credits the same sats a second time, inflating `total-sbtc-staked`/`protocol-bonds-total-staked` without any additional BTC being locked.

Note: I could not fully trace every caller of `verify-l1-lockups` (e.g., all rollover/registration code paths in `pox-5.clar` beyond what was reviewed) to confirm whether an outer guard elsewhere blocks resubmission; this should be verified against the full `register-for-bond`/`update-bond-registration` implementations before remediation.

### Citations

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2057-2113)
```text
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
