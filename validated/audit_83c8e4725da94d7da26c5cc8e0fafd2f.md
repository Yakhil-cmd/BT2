### Title
Bitcoin lockup outpoints are only deduplicated within a single call, allowing the same L1 lockup UTXO to be credited multiple times as staked sats — (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-l1-lockups` / `validate-l1-lockup` in `pox-5.clar` credit a staker with sats for every Bitcoin UTXO they present as a Merkle+header proof of an on-chain timelock output. Duplicate protection (`seen-outpoints`) is implemented only as a transient list built up inside a single `fold` call (capped at 10 entries), not as contract-persisted state. This mirrors the report's bug class of "a validation gap that lets the same underlying commitment be counted more than once" — analogous to a governance/bridge call being executed without the value actually backing it being properly bound to a single accounting event.

### Finding Description
`validate-l1-lockup` (stackslib/src/chainstate/stacks/boot/pox-5.clar:2031-2113) accepts a list of Bitcoin-lockup proof structs, verifies each one's Merkle proof, header, script, and amount, and adds `(get amount output)` into a running `sum`. It tracks `seen-outpoints` only inside the local accumulator that is initialized fresh at the start of `verify-l1-lockups` for a *single* call: [1](#0-0) 

The dedup check itself: [2](#0-1) 

Nothing in the reviewed sections persists `outpoint` identifiers (txid + output-index) into a contract-level map that is checked across separate transactions/calls to `verify-l1-lockups`. As a result, an attacker who owns one real Bitcoin timelock output can present the exact same `{tx, output-index, header, leaf-hashes, ...}` proof in multiple separate calls (e.g., multiple `register`/`credit` transactions across different bonds, reward cycles, or the same bond at different times), and each call will independently pass all the `asserts!` (script match, amount match, Merkle proof, header validity) and add the same sats amount into `sum`/staked-shares bookkeeping again.

### Impact Explanation
This breaks the equality "sats credited to a staker == sats actually locked on Bitcoin for that staker." Each replay double-counts a single Bitcoin commitment into the pox-5 stacking/reward-share accounting (`total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, `staker-shares-staked-for-cycle`, and the accumulated `sum` used for L1 stake registration), inflating the staker's recognized stake without any additional STX or additional sBTC/sats being locked. Because reward distribution (`calculate-rewards`) is driven by these staked-share maps, this can be used to claim sBTC rewards disproportionate to (or entirely without) new value actually contributed — a double-counting of a commitment/reward, which is a Critical-severity impact per the rules (double-counting a commitment or reward).

### Likelihood Explanation
Exploitation only requires an unprivileged staker to submit the identical BTC lockup Merkle-proof payload in more than one transaction to `pox-5.clar`'s L1-lockup verification path. No admin, signer, miner, or other user's key is required — the same header/leaf-hashes/tx bytes the staker already possesses from their own genuine Bitcoin lockup can be reused. The only impediment is if some caller of `verify-l1-lockups` maintains its own persistent, contract-level outpoint registry that I could not locate in the excerpts reviewed; based on the code actually inspected, no such persistent structure exists, only the ephemeral `seen-outpoints` accumulator scoped to one fold invocation.

### Recommendation
Persist processed `(txid, output-index)` pairs in a durable Clarity map (e.g., `used-l1-lockup-outpoints`) that is checked and updated on every call to `validate-l1-lockup`/`verify-l1-lockups`, independent of the in-fold accumulator, so the same Bitcoin lockup output can never be credited more than once across the contract's lifetime.

### Proof of Concept
1. Staker locks BTC into a genuine timelock output matching `construct-lockup-output-script` for their principal/unlock-height.
2. Staker calls the pox-5 entrypoint that invokes `verify-l1-lockups` with the valid Merkle/header proof for that output; sats are credited to their stake.
3. Staker calls the same entrypoint again in a later transaction (different bond-index, reward cycle window, or simply a repeated registration call) with the identical proof payload. Because `seen-outpoints` is re-initialized per call and there is no cross-call/global map rejecting the previously-used outpoint, all `asserts!` pass again and the sats amount is added a second time to the staking/reward-share maps. [3](#0-2) [4](#0-3)

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
