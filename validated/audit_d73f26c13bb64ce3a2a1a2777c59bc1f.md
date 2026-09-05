### Title
Double-counting of Bitcoin L1 lockup proofs allows repeated sBTC-stake credit for the same on-chain output - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`verify-l1-lockups` / `validate-l1-lockup` in `pox-5.clar` validate that a Bitcoin transaction output actually locked sats to a staker's timelock script, then credit the `sum` of those outputs as the staker's staked sats. The de-duplication of Bitcoin outpoints (`seen-outpoints`) is only tracked transiently inside a single call's `fold`, seeded fresh from `(list)` every time the function runs, with no contract-level persistent map recording outpoints that have already been credited across separate calls/transactions.

### Finding Description
`verify-l1-lockups` builds its `seen-outpoints` accumulator starting from an empty list on every invocation: [1](#0-0) 

`validate-l1-lockup` only rejects an outpoint if it is already present in that same call's local `seen-outpoints` accumulator, and otherwise appends the credited amount to `sum`: [2](#0-1) 

There is no persistent, contract-wide map (analogous to a "used/spent outpoint" registry) that records a Bitcoin outpoint as already claimed once its sats have been credited to a staker. Because the duplicate check resets on every call, a staker can submit the exact same Bitcoin lockup transaction/output (same merkle proof, same header, same outpoint) in multiple separate registration calls — e.g. across different `bond-index` values, or in repeated calls before the corresponding bond starts — and have the same real BTC lock counted as `sats` staked more than once. This breaks the equality that staked sats recorded on Stacks must equal sats actually and currently locked on the Bitcoin L1 output; the same L1 commitment gets double-counted into multiple stake positions.

This is the direct structural analog of the external report's root cause: a value used to determine credited/rewarded amounts (there, `msg.value - fees`; here, the sum of validated L1 lockups) is computed without correctly excluding value that should not be double-attributed, because the "already used" check is scoped too narrowly (per-transaction list vs. global state).

### Impact Explanation
If a single Bitcoin lockup output can be credited into more than one bond/stake position, the staker's on-chain shares (`total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, `staker-shares-staked-for-cycle`) and hence reward entitlements and signing weight will exceed the sats that are actually locked on Bitcoin. This double-counts a commitment and inflates reward/signing weight beyond backed value — matching the "High" impact category (signing weight or reward slots exceeding locked value; double-counting a commitment).

### Likelihood Explanation
Any staker who controls a Bitcoin timelock output can trigger this by calling the registration path (which invokes `verify-l1-lockups`) more than once with the same proof data, e.g. across multiple `bond-index`s or during a rollover flow, since only local, ephemeral de-duplication is enforced — this requires no privileged role, no other party's key, and no unusual preconditions beyond controlling one's own valid lockup proof.

### Recommendation
Persist a contract-level map of consumed L1 outpoints (e.g. `used-lockup-outpoints: {txid, output-index} -> bool`) that is checked and updated atomically the first time an outpoint's sats are credited to any staker/bond, and reject `validate-l1-lockup` if the outpoint is already marked used, instead of relying solely on the per-call `seen-outpoints` fold accumulator.

### Proof of Concept
1. Staker generates one valid Bitcoin lockup output/proof (`tx`, `header`, `output-index`, merkle proof) satisfying `construct-lockup-output-script` for their `staker-unlock-bytes`.
2. Staker calls the registration entrypoint that invokes `verify-l1-lockups` for `bond-index = A`, submitting this proof; `validate-l1-lockup` passes (script/amount/merkle/header/duplicate checks all succeed since `seen-outpoints` starts empty) and the sats are credited via `add-staker-to-bond-cycles`.
2. Staker calls the same registration entrypoint again for a different `bond-index = B` (or in a later block against another bond) submitting the identical proof/outpoint.
3. Because `seen-outpoints` is re-initialized to `(list)` for this new call, the duplicate check does not fire, and the identical Bitcoin output is credited a second time into an independent stake position — doubling the staker's recorded sats without any additional BTC being locked. [3](#0-2) [4](#0-3)

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2072-2113)
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
)
```
