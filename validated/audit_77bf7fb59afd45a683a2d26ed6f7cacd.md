## Title
L1 Bitcoin lockup proofs can be replayed across multiple `register-for-bond` calls to double-count sats never re-locked on Bitcoin - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`register-for-bond` in `pox-5.clar` accepts an L1 Bitcoin lockup proof (`btc-lockup`) and, via `verify-l1-lockups`/`validate-l1-lockup`, checks that each Bitcoin output is a valid, unspent-looking timelock and rejects duplicate outpoints *within the same call*, but there is no contract-persisted map recording which `(txid, output-index)` pairs have already been credited by a *previous* `register-for-bond` transaction. The same Bitcoin lockup proof can therefore be resubmitted in later transactions to be credited as `sats-total` again.

### Finding Description
`verify-l1-lockups` [1](#0-0)  folds over the supplied outputs via `validate-l1-lockup`, which tracks `seen-outpoints` only inside the `fold` accumulator for that single call, checking `(is-none (index-of? seen-outpoints outpoint))` [2](#0-1) . This "calculates but doesn't compare against prior state" pattern is exactly the bug class described in the external report (hash calculated, but never checked against a persisted prior value). Here, the equality/inclusion check (`is-none (index-of? seen-outpoints outpoint))`) is performed only against a locally-built, per-transaction list, not against any durable map of previously-credited outpoints. No `define-map` exists in `pox-5.clar` that records used L1 outpoints (grep for `outpoint`/`used-outpoint` across the file returns only the in-fold `seen-outpoints` references), so nothing prevents the *same* Bitcoin transaction/output from being presented again in a subsequent `register-for-bond` call.

`register-for-bond` uses the returned `sats-total` to set `protocol-bond-memberships`, increment `protocol-bonds-total-staked`, and drive `add-staker-to-bond-cycles`/`add-staker-to-signer-cycles` (i.e., it directly increases the staker's credited stake and the contract's total sBTC/L1-backed staked amount) [3](#0-2) . Because the proof itself is just static, already-mined Bitcoin block/tx data (`header`, `tx`, `leaf-hashes`, etc.), an attacker who once locked BTC can keep re-presenting the identical proof in new `register-for-bond` transactions (e.g., for later bond periods after allowance/membership state is cleared) and have the same physical BTC lockup counted as backing multiple, or successive, PoX-5 bond memberships without ever creating a new BTC lock.

### Impact Explanation
This breaks the equality that "sats credited toward a bond = sats actually and currently locked on Bitcoin for that stake." Reusing a stale/expired L1 proof allows sats to be double-counted as collateral for a new bond period while the underlying BTC may already be unlocked or already counted for a previous bond — i.e., "sats credited by an L1 proof that were never (still) locked on Bitcoin" and "double-counting a commitment." This directly inflates `protocol-bonds-total-staked` / a staker's `amount-sats`, which back reward-slot weighting and allowlist consumption, without new value backing it — a Critical-class issue per the given rubric (double-counting a commitment/reward, or reward slots exceeding locked value).

### Likelihood Explanation
Likelihood is moderate-to-high: the attacker only needs to retain and resubmit the same proof data (public, already-observed by the L1 verification logic in the contract) into a later `register-for-bond` call. The `allowlist`/`protocol-bond-allowances` mechanism gates *who* can register and up to what `max-sats`, but does not gate *which* Bitcoin outpoints can be reused, so an allowlisted staker (which is within the "unprivileged account" scope — a normal staker calling a public function) can repeat this across every bond period they're allowlisted for.

### Recommendation
Persist a durable map (e.g., `used-l1-lockup-outpoints: {txid: (buff 32), output-index: uint} -> bool`, or scoped per-staker/per-bond as appropriate) and check + insert into it inside `validate-l1-lockup` (or `verify-l1-lockups`) so that an outpoint already credited in any prior transaction is rejected with `ERR_DUPLICATE_LOCKUP_OUTPOINT`, mirroring how `used-signer-key-authorizations` prevents signature/authorization replay in `pox-4.clar` [4](#0-3) .

### Proof of Concept
1. Attacker `A` obtains a valid L1 lockup proof (`height`, `tx`, `output-index`, `header`, `leaf-hashes`, `tx-count`, `tx-index`, `amount`, `unlock-burn-height`) for a genuine BTC timelock output.
2. `A` calls `register-for-bond` for `bond-index = 0` with this proof; `verify-l1-lockups`/`validate-l1-lockup` accepts it (script, amount, merkle proof, unlock height all check out) and credits `sats-total` sats [5](#0-4) .
3. After bond 0's term, `A`'s `protocol-bond-memberships` may be cleared/rolled (per the roll-over logic), or `A` is re-allowlisted for a later `bond-index`.
4. `A` calls `register-for-bond` again for the new `bond-index` with the *identical* proof (same `tx`/`output-index`/`header`). Since `seen-outpoints` only guards duplicates within the current call's `outputs` list (max 10 entries) and there is no persisted cross-call map, `validate-l1-lockup` re-validates the same outpoint successfully and `sats-total` is credited again, incrementing `protocol-bonds-total-staked` for the new bond without any new BTC being locked.

**Caveat:** I could not find (within the indexed portion of `pox-5.clar`) any other mechanism elsewhere in the contract (e.g., in `unstake-sbtc`/bond-expiry cleanup) that clears or invalidates an outpoint once used; my search of `define-map` entries in the file and of "outpoint" usages found no persisted replay-protection map. If such a check exists in code outside what the index returned, this finding would need to be revisited, so I recommend a maintainer explicitly confirm the absence of any persistent per-outpoint usage tracking in `pox-5.clar` before treating this as fully confirmed.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L672-795)
```text
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
        )
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))
        ;; Verify that they're sending enough STX
        (asserts!
            (>= amount-ustx
                (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
                    (get min-ustx-ratio bond)
                ))
            ERR_INSUFFICIENT_STX
        )

        ;; Verify that the bond hasn't started
        (asserts! (< burn-block-height bond-start-height)
            ERR_BOND_ALREADY_STARTED
        )

        ;; An existing STX-only stake is allowed only if its term ends no
        ;; later than this bond's first reward cycle (no overlap). A stx-only
        ;; stake has no L1 collateral, so there's no L1-unlock-window gate
        ;; here -- the lock just extends forward via the node-side handler.
        (asserts!
            (match existing-stake
                stake-info (<=
                    (+ (get first-reward-cycle stake-info)
                        (get num-cycles stake-info)
                    )
                    first-reward-cycle
                )
                true
            )
            ERR_ALREADY_STAKED
        )

        ;; Cannot stake more sats than their allowance
        (asserts! (<= sats-total allowance) ERR_TOO_MUCH_SATS)

        ;; Must have enough unlocked STX
        ;;  the Staker must have sufficient total funds (locked + unlocked).
        ;;  On a roll-over the staker's STX is still locked by the ending
        ;;  bond; the node-side handler extends that lock to the new amount,
        ;;  so checking only `stx-get-balance` (unlocked) would falsely fail.
        (asserts! (>= total-balance amount-ustx) ERR_INSUFFICIENT_STX)

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1
            amount-ustx sats-total true signer-calldata
        ))

        ;; The signer must have been registered already, and its signer key
        ;; grant must still be active.
        (try! (verify-signer-key-grant signer
            (unwrap! (get-signer-info signer) ERR_SIGNER_NOT_FOUND)
        ))

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
```

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

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L765-788)
```text
;; This function does two things:
;;
;; - Verify that a signer key is authorized to be used
;; - Updates the `used-signer-key-authorizations` map to prevent reuse
;;
;; This "wrapper" method around `verify-signer-key-sig` allows that function to remain
;; read-only, so that it can be used by clients as a sanity check before submitting a transaction.
(define-private (consume-signer-key-authorization (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                                  (reward-cycle uint)
                                                  (topic (string-ascii 14))
                                                  (period uint)
                                                  (signer-sig-opt (optional (buff 65)))
                                                  (signer-key (buff 33))
                                                  (amount uint)
                                                  (max-amount uint)
                                                  (auth-id uint))
  (begin
    ;; verify the authorization
    (try! (verify-signer-key-sig pox-addr reward-cycle topic period signer-sig-opt signer-key amount max-amount auth-id))
    ;; update the `used-signer-key-authorizations` map
    (asserts! (map-insert used-signer-key-authorizations
      { signer-key: signer-key, reward-cycle: reward-cycle, topic: topic, period: period, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount } true)
      (err ERR_SIGNER_AUTH_USED))
    (ok true)))
```
