Confirmed: there is no global or persistent record of which Bitcoin outpoints have already been used to back a `register-for-bond` L1 lockup. The only de-duplication is the `seen-outpoints` accumulator inside `validate-l1-lockup`, which is scoped to a single call's `outputs` list [1](#0-0) , and the only "already registered" protection is `bond-overlaps-new-position?`, which is keyed on the calling staker's single `protocol-bond-memberships` entry and only blocks a *new* registration whose reward-cycle window overlaps an *existing, still-active* membership [2](#0-1) .

### Title
Reusable L1 BTC-lockup proofs allow the same locked sats to be re-credited across sequential bonds - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond`'s L1 path (`verify-l1-lockups` → `validate-l1-lockup`) proves that a Bitcoin output exists, is unspent-format (script/amount match), and is chained to a valid block header/merkle proof, but it never marks that Bitcoin outpoint as consumed at the contract level. Once a bond membership using an L1 proof ends (i.e., no longer "overlaps" per `bond-overlaps-new-position?`), the exact same `tx`/`output-index`/`header`/`leaf-hashes` tuple can be resubmitted in a brand-new `register-for-bond` call for a later `bond-index`, crediting the identical, never-respent BTC lockup as fresh collateral again.

### Finding Description
`validate-l1-lockup` verifies: the P2WSH script matches `construct-lockup-output-script` for the `staker`/`unlock-burn-height` pair [3](#0-2) , that the block header/merkle proof are valid [4](#0-3) , and dedups only *within* the current call's `outputs` list via `seen-outpoints` [5](#0-4) . There is no map recording that a given `(txid, output-index)` has already been consumed by a prior successful `register-for-bond`. The only anti-replay control is `bond-overlaps-new-position?`, which merely prevents the *same staker* from holding two *overlapping-in-time* memberships [6](#0-5) . Once the first bond's term ends (and its `protocol-bond-memberships` entry is superseded/cleared through a later call), nothing stops the staker from calling `register-for-bond` again with the identical lockup proof for a new `bond-index`, as long as `unlock-burn-height` (a user-supplied field of the proof, not re-derived from the new bond) satisfies `(>= unlock-burn-height (get-bond-l1-unlock-height bond-index))` [7](#0-6) . Since the contract never custodies L1-backed BTC (unlike the sBTC path, where `roll-sbtc` actually moves tokens [8](#0-7) ), there is no on-chain event that would force the BTC to move or become otherwise unusable between bonds — the staker can simply never spend the timelocked UTXO on Bitcoin and keep reusing the proof.

### Impact Explanation
This lets a staker recognize the same L1-locked sats as new stake/collateral for more than one bond period without ever locking additional BTC. Because `sats-total` from the L1 proof directly drives `min-ustx-for-sats-amount`-gated STX-lock sizing, `protocol-bonds-total-staked`, and per-cycle signer/staker share accounting (`add-staker-to-bond-cycles`, `add-staker-to-signer-cycles`) [9](#0-8) , this is a double-count of a BTC commitment across bond terms: the reward/weight system treats one real BTC lockup as backing two (or more) sequential bond memberships. This breaks the equality "sats credited by the contract == sats actually newly locked on Bitcoin for that period," and can inflate a staker's reward-slot weight/signing weight beyond what their locked value actually supports.

### Likelihood Explanation
Requires only an unprivileged staker who already possesses a valid, allow-listed L1 lockup proof and is willing to not spend the underlying BTC. No admin, miner, or other user's key is needed — the staker only needs to be present on a bond's allowlist (`protocol-bond-allowances`) for both registrations, which is realistic for a repeat/long-term participant, and the exploit is simply re-submitting the same historical proof data in a later transaction after their prior bond term has run its course.

### Recommendation
Persist a durable, contract-level record (e.g., a map keyed on `{txid, output-index}`) of every L1 outpoint that has ever been successfully credited via `validate-l1-lockup`/`register-for-bond`, and reject reuse of any previously-consumed outpoint regardless of whether the staker's prior membership has since ended, mirroring the per-call `seen-outpoints` dedup but made persistent and global rather than scoped to a single call's fold.

### Proof of Concept
1. Staker locks `N` sats into the canonical P2WSH timelock script for a given `unlock-burn-height` H, and never spends it on Bitcoin.
2. Staker calls `register-for-bond` for `bond-index: 0` with the L1 proof; membership is created, sats/weight are credited for bond 0's term.
3. Bond 0's term ends; the staker's `protocol-bond-memberships` entry is cleared/superseded (e.g., via a later `stake`/rollover call, or simply because `bond-overlaps-new-position?` no longer flags an overlap with a later bond).
4. Staker calls `register-for-bond` again for a later, non-overlapping `bond-index` (e.g., `bond-index: 12`), submitting the exact same `tx`, `output-index`, `header`, `leaf-hashes`, and `unlock-burn-height: H` (satisfying `H >= get-bond-l1-unlock-height(12)` if H is far enough in the future, which is easy to arrange when initially locking BTC for a long duration).
5. `validate-l1-lockup` re-verifies script/merkle/header successfully (nothing has changed on Bitcoin), and the contract credits the same `N` sats again as fresh collateral for bond 12 — double-counting one real BTC lockup across two bond periods.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L764-770)
```text
        ;; Reject if an existing membership *overlaps* this bond. An existing
        ;; bond whose staking term ends no later than this bond's first cycle
        ;; (e.g. rolling from bond N into bond N+6) is allowed.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_REGISTERED
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L793-805)
```text
        (map-set protocol-bonds-total-staked bond-index
            (+ current-total-staked sats-total)
        )
        ;; A roll-over from an ending bond ADDS the new bond's shares but does
        ;; NOT tear down the old bond's per-cycle shares/delegation (unlike
        ;; `update-bond-registration`, which removes then re-adds).
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            BOND_LENGTH_CYCLES sats-total
        ))

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            BOND_LENGTH_CYCLES amount-ustx false
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1943-1978)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2057-2085)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2086-2088)
```text
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2089-2103)
```text
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2983-3000)
```text
(define-read-only (bond-overlaps-new-position?
        (existing-membership (optional {
            bond-index: uint,
            amount-ustx: uint,
            signer: principal,
            is-l1-lock: bool,
            amount-sats: uint,
        }))
        (new-first-reward-cycle uint)
    )
    (match existing-membership
        existing (>
            (+ BOND_LENGTH_CYCLES
                (bond-period-to-reward-cycle (get bond-index existing))
            )
            new-first-reward-cycle
        )
        false
```
