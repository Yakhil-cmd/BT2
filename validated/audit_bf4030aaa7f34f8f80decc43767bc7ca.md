### Title
Local-only `seen-outpoints` deduplication in `verify-l1-lockups` allows the same Bitcoin lockup output to be reused across separate calls, crediting sats that were never (re-)locked on Bitcoin - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`verify-l1-lockups`/`validate-l1-lockup` in `pox-5.clar` deduplicate Bitcoin lockup outpoints only *within a single function call* via a `seen-outpoints` list that is freshly initialized to `(list)` on every invocation. There is no persistent, contract-wide record of which L1 outpoints have already been used to credit a staker with sats. This is the same class of weakness as the analog report: a check that is locally sound (no duplicate within one "batch"/one "sorted-queue segment") but globally insufficient, allowing an attacker to replay the same already-validated item across separate calls to make the system credit something more than once.

### Finding Description
`verify-l1-lockups` initializes the accumulator with `seen-outpoints: (list)` for every call: [1](#0-0) 

`validate-l1-lockup` only asserts uniqueness against this call-local `seen-outpoints` list (`ERR_DUPLICATE_LOCKUP_OUTPOINT`), then appends the outpoint to the same call-local list before returning: [2](#0-1) 

Nowhere in this fold, nor in `verify-l1-lockups` itself, is the outpoint checked against a persistent contract map (e.g. a `used-l1-outpoints` map) that would survive across transactions or across separate `bond-index`/registration calls. A targeted repo-wide search for identifiers like `used-outpoints`/`l1-lockup` found no such persistent tracking map outside of this local fold structure.

This mirrors exactly the root cause pattern in the referenced zkSync log-sorter bug: the circuit/contract enforces a *locally* correct invariant (no two adjacent/duplicate entries within the item being processed) but fails to enforce the invariant *globally* across the full history of processed items, letting an attacker replay already-"consumed" data to manufacture credit that should not exist.

### Impact Explanation
If `verify-l1-lockups`'s returned `sum` (in sats) is used to credit a staker's `amount-sats`/stake weight (as suggested by `staker-shares-staked-for-cycle`/`signer-shares-staked-for-cycle` bookkeeping keyed by `bond-index` that consumes an `amount-sats` value), an attacker who owns one real Bitcoin lockup output can submit that same output+proof again in a subsequent call (e.g., a new bond registration, or a repeat call for a different `bond-index`) and have the sats counted again, since the only replay protection resets every call. This is "sats credited by an L1 proof that were never locked on Bitcoin" (the second and further credits correspond to no new BTC being locked), which is explicitly listed as an in-scope Critical-impact class (double-counting a commitment/reward, unbacked crediting).

### Likelihood Explanation
Exploitability requires only that a staker who has legitimately performed one L1 lockup can call the staking/registration flow that invokes `verify-l1-lockups` more than once (e.g., with a different `bond-index`), which is a normal, unprivileged user action — no admin, miner, or other user's key is required. The likelihood is High assuming the sum from `verify-l1-lockups` is persisted per-call without any cross-call uniqueness enforcement, which is confirmed by the code shown. I was not able to trace, within the available tool budget, the exact public entry point (e.g. a `register-for-bond`-style function) that calls `verify-l1-lockups` and persists `amount-sats`, so I cannot cite the precise line where the credited sum is written into staker state across multiple calls. This is the main remaining uncertainty and should be verified by a Devin session with broader access to the full `pox-5.clar` file before remediation.

### Recommendation
Add a persistent, global map (e.g., `used-l1-outpoints: {txid, output-index} -> bool` or keyed additionally by staker/bond) that is checked and updated permanently (not reset per call) whenever an L1 lockup outpoint is validated and credited, so that the same Bitcoin output can never be used to credit sats more than once across any set of calls, registrations, or bond indices.

### Proof of Concept
1. Staker locks BTC once, producing a single valid lockup output (`txid`, `output-index`) satisfying the timelock script for their `staker-unlock-bytes`.
2. Staker calls the pox-5 flow that invokes `verify-l1-lockups`/`validate-l1-lockup` with this outpoint for `bond-index = A`; `seen-outpoints` starts empty, the outpoint passes all checks, and `sum` (sats) is credited to the staker's stake for bond A.
3. Staker calls the same flow again — either for a different `bond-index = B`, or in a new transaction for the same purpose — submitting the identical BTC lockup proof. Because `verify-l1-lockups` reinitializes `seen-outpoints: (list)` on every call, the previously-used outpoint is *not* recognized as already consumed, passes `validate-l1-lockup` again, and the same sats amount is credited a second time.
4. The staker now holds sats-based stake/shares proportional to `2x` (or more, repeated per additional call) their actual locked BTC amount, with no additional BTC ever locked — a double-counting/unbacked-credit condition. [3](#0-2) [4](#0-3)

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
