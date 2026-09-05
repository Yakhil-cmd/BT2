### Title
`register-for-bond` L1 lockup proof lacks a global once-only check on Bitcoin outpoints, allowing the same on-chain BTC lock to be replayed to credit sats to multiple bonds — ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`register-for-bond`'s L1 path (`verify-l1-lockups` / `validate-l1-lockup`) only proves that a given Bitcoin `(txid, output-index)` outpoint once existed in a valid block with the expected timelock script and amount. It never records that outpoint in persistent contract state, so nothing prevents the exact same historical outpoint from being submitted again in a later, independent `register-for-bond` call to credit `amount-sats` a second time.

### Finding Description
`validate-l1-lockup` maintains a `seen-outpoints` list, but that list lives only in the fold accumulator created fresh inside `verify-l1-lockups` for the single call: [1](#0-0) 

Its dedup comment is explicit that it only guards duplicates "in this call": [2](#0-1) 

The actual validation in `validate-l1-lockup` checks the block header, merkle inclusion, script hash, and amount — but never queries or writes to any *persistent* map keyed by `(txid, output-index)`: [3](#0-2) 

I searched the contract for any global outpoint-tracking map (`l1-outpoint`, `outpoint-used`, `spent`, `utxo`, etc.) and found none — `seen-outpoints` is the only outpoint bookkeeping in the file, and it is scoped to the single fold call.

Because the lockup script is deterministic — `construct-lockup-output-script(staker, unlock-burn-height, staker-unlock-bytes, early-unlock-bytes)` — the same staker's one real on-chain BTC lock can be proven valid in as many separate `register-for-bond` transactions as the staker likes (once any previous bond membership has ended/rolled over, or if a differently-configured bond happens to accept the same unlock height/bytes). Each successful call credits `sats-total` toward that bond's `protocol-bonds-total-staked` and the staker's own membership (`amount-sats`), and unlocks a corresponding amount of STX via `min-ustx-for-sats-amount`, without any check that the Bitcoin output is still unspent or that it hasn't already been "consumed" as collateral for a prior/other membership: [4](#0-3) 

This is the direct analog of the ironfish nullifier-reuse bug: there, a spent note's nullifier wasn't tracked against the transaction that actually spent it, letting an expiring transaction "unspend" a note that had already been spent elsewhere, double-counting the same underlying value. Here, the "nullifier" equivalent — the Bitcoin outpoint — is never durably marked as consumed by the pox-5 contract, so the same underlying locked BTC can be double-counted as collateral across multiple bond registrations.

### Impact Explanation
This breaks the equality "sats credited to a bond membership == sats actually locked on Bitcoin for that membership." A staker can obtain bond membership (and the associated STX-lock / signer-slot / reward eligibility) for more bonds than their actual BTC collateral justifies, or reuse the same collateral proof after having already exited/rolled it into a different bond. That is unbacked crediting of stake, matching the Critical bucket ("sats credited by an L1 proof that were never locked on Bitcoin", "double-counting a commitment") and could also cause temporary/permanent freezing or slot-count exceeding locked value for other honest bond participants who share threshold-based reward slots.

### Likelihood Explanation
Exploitability requires only that the attacker control a Bitcoin timelock script for themselves (any staker naturally does, since the script is a function of their own principal and chosen unlock bytes), and that they can arrange to call `register-for-bond` more than once referencing the same outpoint — which the contract's own rules permit once a prior membership for that staker has ended (non-overlapping bond) or via a rollover into a later bond. No additional bond admin, miner, or third-party key is required — this is fully reachable by an ordinary allow-listed staker. Because the check operates purely on static SPV/merkle proof validity rather than current UTXO status, likelihood is high once the sequencing/timing conditions (non-overlapping bond periods) are met.

### Recommendation
Add a persistent, contract-wide map (e.g. `l1-lockup-outpoints-used: {txid, output-index} -> bool`) and have `validate-l1-lockup` `map-insert` (asserting success) each outpoint the first time it's credited, rejecting any future `register-for-bond` call — for this staker or any other bond — that references an outpoint already recorded as used, with the same `ERR_DUPLICATE_LOCKUP_OUTPOINT` semantics but at global rather than per-call scope.

### Proof of Concept
1. Staker Alice locks BTC in the canonical P2WSH timelock output (txid T, output-index 0) for bond 0, with `unlock-burn-height = H0` satisfying bond 0's minimum unlock height.
2. Alice calls `register-for-bond(bond-index=0, ..., btc-lockup=ok({outputs:[T:0], ...}))`. `verify-l1-lockups`/`validate-l1-lockup` prove T:0 is a valid, correctly-scripted, correctly-amounted lockup and credit `amount-sats` to bond 0; Alice's STX is locked and she becomes a member of bond 0's signer set.
3. Bond 0's term ends (or Alice performs a legitimate rollover) so `existing-membership` no longer overlaps a new bond's first-reward-cycle (per `bond-overlaps-new-position?`).
4. Alice calls `register-for-bond(bond-index=6, ..., btc-lockup=ok({outputs:[T:0], ...}))` again, presenting the *same* Bitcoin outpoint T:0 (which requires `H0 >= get-bond-l1-unlock-height(6)`, achievable if bond 6's minimum unlock height is not stricter, or Alice chose a sufficiently large `H0` up front). `validate-l1-lockup` performs the exact same static checks and succeeds again — there is no map lookup rejecting a previously-credited outpoint — crediting `amount-sats` to bond 6 as well, from the same single BTC lock.
5. Result: two separate bond memberships (and their associated STX locks / signer weight) are backed by one BTC lockup, double-counting the collateral.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-792)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2021-2030)
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
