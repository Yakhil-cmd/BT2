### Title
Reusable L1 Bitcoin Lockup Proofs Allow Double-Counting of BTC Collateral Across Protocol Bonds — (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond` accepts a list of Bitcoin-lockup proofs (`btc-lockup`) and credits `sats-total` sats of BTC collateral toward a new protocol bond after validating each output via `verify-l1-lockups` → `validate-l1-lockup`. The only duplicate-outpoint protection (`seen-outpoints`) is scoped to a single call's fold accumulator, not persisted anywhere in contract storage. Because a Bitcoin merkle/header proof for a real, historical transaction remains valid forever (the chain state it proves never changes), the exact same `(txid, output-index)` lockup can be resubmitted in a completely separate, later `register-for-bond` call — for a new bond period — and will pass validation again, crediting the same, single BTC lockup toward a second bond's `sats-total`/weight.

### Finding Description
`validate-l1-lockup` (`pox-5.clar` lines 2031-2113) checks that an outpoint hasn't already appeared within the *same* `fold` call via `seen-outpoints`: [1](#0-0) 

This list is initialized fresh on every invocation of `verify-l1-lockups`: [2](#0-1) 

There is no contract map recording previously-used `(txid, output-index)` pairs across separate transactions/calls (confirmed by grep: no `used-l1-outpoint`/global-outpoint map exists in `pox-5.clar`). The only per-staker guard is `ERR_ALREADY_REGISTERED`, which blocks a *second concurrent* membership for the same staker, but once a bond period ends and the staker's membership is cleared (rollover or normal unlock), nothing prevents the staker from calling `register-for-bond` again for a new `bond-index` and submitting the identical lockup proof (same header, same merkle path, same output) that was already used to justify a prior bond's sats: [3](#0-2) 

The proof only re-validates that the output's script matches `construct-lockup-output-script` for the *claimed* staker/unlock-height and that the merkle proof is valid against the (immutable, historical) block header — it says nothing about whether the underlying BTC is still locked, unspent, or not already counted by a prior/expired bond. Since Bitcoin history is permanent, this same evidence can be replayed indefinitely.

### Impact Explanation
Each successful `verify-l1-lockups` credits `sats-total`, which feeds directly into `amount-ustx`/stake-weight accounting for the new bond (`min-ustx-for-sats-amount`, `sats-total`, `total-shares-staked-for-cycle`, etc.): [4](#0-3) 

A staker can therefore back multiple, sequential (or, if timing/rollover windows permit, potentially overlapping) protocol bonds with a single real BTC lockup, receiving reward/stake credit each time without any additional BTC ever being locked. This double-counts a single BTC commitment across the reward-weight/signer-set calculation pipeline that ultimately flows into `signer_set.rs` (`pox_5_stake_entries`, `pox_5_make_signer_set`), inflating a signer's counted stake relative to real locked collateral — an unbacked-credit condition matching the "double-counting a commitment" criterion.

### Likelihood Explanation
Exploitable by any allow-listed staker with no privileged role required — they need only keep the original lockup's block header, merkle-proof data, and raw transaction (all public, permanently available from the Bitcoin chain) and resubmit them in a subsequent `register-for-bond` call for a different `bond-index` after their prior bond membership ends. The likelihood is high for any staker who intends to participate in consecutive bond periods, since replay is trivial and requires no additional on-chain action.

### Recommendation
Persist a global (not call-scoped) map of consumed L1 outpoints (e.g., `{ txid, output-index } -> bond-index / consumed-at-cycle`) and reject any `register-for-bond` proof whose outpoint has already been credited to any bond, regardless of whether that bond has since ended. Alternatively, require proof that the UTXO is still unspent at call time (not just that it once existed), or bind the credited sats to a single, exclusive, non-renewable claim per outpoint for the lifetime of the contract.

### Proof of Concept
1. Staker locks `X` sats into the canonical P2WSH timelock output for `bond-index=0`, matching `construct-lockup-output-script`.
2. Staker calls `register-for-bond(bond-index=0, ...)` with a valid Bitcoin merkle/header proof of that output; `sats-total = X` is credited, bond membership created.
3. Bond 0's period ends; staker's membership is cleared/rolled over via normal unlock flow.
4. Staker calls `register-for-bond(bond-index=N, ...)` for a later bond period `N`, submitting the **same** header/tx/merkle-proof/output-index from step 1 (still valid, since Bitcoin history never changes) and satisfying `>= minimum-unlock-height` for bond `N`.
5. `validate-l1-lockup` passes all checks (script match, amount match, unique-within-this-call, header/merkle verify) since `seen-outpoints` was reset for this new call; `sats-total = X` is credited again to bond `N`, even though no new BTC was locked. [5](#0-4)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L642-708)
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
            ;; Any bond the staker is currently a member of. Some value here
            ;; means this is a roll-over from an ending bond into a later one.
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
            ;; sBTC currently custodied for the staker's existing bond (0 if
            ;; they have none, or if the existing bond is an L1 lock).
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
            ;; Any STX-only stake the staker has. Present means this
            ;; `register-for-bond` is a roll-over from an ending stx-only
            ;; stake into a bond.
            (existing-stake (map-get? staker-info tx-sender))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (allowance (unwrap!
                (map-get? protocol-bond-allowances {
                    staker: tx-sender,
                    bond-index: bond-index,
                })
                ERR_NOT_ALLOWLISTED
            ))
            (first-reward-cycle (bond-period-to-reward-cycle bond-index))
            (bond-start-height (bond-period-to-burn-height bond-index))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle BOND_LENGTH_CYCLES))
            (current-total-staked (get-total-shares-staked-for-cycle first-reward-cycle
                (some bond-index)
            ))
            (stx-balance (stx-account tx-sender))
            (total-balance (+ (get locked stx-balance) (get unlocked stx-balance)))
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2057-2112)
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
```
