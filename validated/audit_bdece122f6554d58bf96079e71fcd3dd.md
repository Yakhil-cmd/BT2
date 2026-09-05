### Title
Reused Bitcoin L1 lockup outpoint can be double-counted as bond collateral across separate `register-for-bond` calls - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`pox-5.clar`'s L1-lockup bonding path only deduplicates Bitcoin outpoints *within a single transaction's proof list*, not across separate registrations. The same on-chain BTC lockup UTXO can therefore be submitted as proof-of-lockup more than once over time (across different `register-for-bond` calls), crediting `sats-total` — and the STX amount it unlocks/authorizes — more than once for a single, singular Bitcoin lock.

### Finding Description
`verify-l1-lockups` folds over the caller-supplied list of Bitcoin lockup outputs and calls `validate-l1-lockup` [1](#0-0) . Deduplication of outpoints is implemented purely via the `seen-outpoints` accumulator that is initialized to `(list)` at the start of *each call* to `verify-l1-lockups`, and is only checked with `index-of?` against entries appended during that same fold [2](#0-1) [3](#0-2) .

There is no contract-level persistent map (e.g., `used-l1-outpoints`) that records a Bitcoin `(txid, output-index)` pair as spent/consumed once it has been used to back a bond in one transaction, and a grep of the contract confirms no such map exists [4](#0-3) . Consequently, once a `register-for-bond` call using an L1 lockup succeeds and the bond membership later ends (bond term expiry, unstake, or a subsequent legitimate rollover), the *exact same* Bitcoin outpoint proof (same header/tx/merkle-proof bytes) can be resubmitted in a brand-new `register-for-bond` call. `validate-l1-lockup` will happily re-verify the same on-chain BTC transaction and re-credit `sats-total` for that outpoint, because its only anti-replay check is scoped to the single call's `seen-outpoints` list, not any cross-call state.

This breaks the intended equality that `sats-total` (used to compute `min-ustx-for-sats-amount`, i.e. how much STX is required/how large a bond position is granted) must correspond 1:1 to sats *actually and currently* locked on Bitcoin [5](#0-4) . The same BTC lock can thus back more STX-bond credit than the Bitcoin collateral actually represents once reused.

### Impact Explanation
This falls in the Critical bucket ("sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment") because the sats figure backing a bond's STX requirement/reward eligibility is not guaranteed unique to the underlying Bitcoin UTXO across the contract's lifetime — only within one transaction's list. A staker could re-establish bond membership (once their prior membership has legitimately ended) using stale lockup proof data instead of actually re-locking BTC, misrepresenting their real BTC backing to the protocol's sats-to-STX ratio logic.

### Likelihood Explanation
Exploitation only requires an unprivileged staker to save a previously-used, valid L1 lockup proof and resubmit it in a later `register-for-bond` transaction after their prior bond membership has ended (which is a normal, permission-less lifecycle event). No admin, signer, or victim key is required.

### Recommendation
Add a persistent contract-level map keyed by `(txid, output-index)` (or the full outpoint) that is marked as consumed the first time `validate-l1-lockup` successfully credits it, and have `validate-l1-lockup`/`verify-l1-lockups` assert that the outpoint has not been previously consumed by any prior successful `register-for-bond`/`update-bond-registration` call, independent of the in-call `seen-outpoints` list.

### Proof of Concept
1. Staker A locks `X` sats to the canonical timelock P2WSH script tied to their principal and calls `register-for-bond` with a valid L1 lockup proof referencing outpoint `O` (txid, output-index); `verify-l1-lockups`/`validate-l1-lockup` accept it and credit `sats-total = X`, establishing bond membership [5](#0-4) .
2. That bond membership term ends (bond matures/expires) or A unstakes, clearing `protocol-bond-memberships` for A.
3. A calls `register-for-bond` again (for a new bond period) submitting the identical proof for outpoint `O` (same header/tx/merkle bytes) without having created any new Bitcoin lockup.
4. `verify-l1-lockups` re-initializes `seen-outpoints` to `(list)` for this new call [2](#0-1) , so the dedup check in `validate-l1-lockup` passes again, and `sats-total = X` is credited a second time for the same BTC lock, satisfying the STX/sats ratio check with reused collateral [6](#0-5) .

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L52-70)
```text
;; The lockup amount does not match the specified amount of sats
(define-constant ERR_INVALID_LOCKUP_AMOUNT (err u45))
;; The same Bitcoin outpoint (txid + output-index) appeared twice in
;; the L1 lockup proof list submitted to `register-for-bond`.
(define-constant ERR_DUPLICATE_LOCKUP_OUTPOINT (err u46))
;; A staker tried to modify the next reward cycle's state during the prepare
;; phase.
(define-constant ERR_STAKE_IN_PREPARE_PHASE (err u47))
;; A staker tried to rollover a bond too early
(define-constant ERR_ROLLOVER_TOO_EARLY (err u48))
;; A reentrant call into pox-5 was detected while a signer-manager call was in flight
(define-constant ERR_REENTRANT_CALL (err u49))
;; The staker already announced an L1 early exit for this bond period
(define-constant ERR_L1_EARLY_EXIT_ALREADY_ANNOUNCED (err u50))
;; A reserve withdrawal was attempted with insufficient reserve balance
(define-constant ERR_INSUFFICIENT_RESERVE_BALANCE (err u51))
;; The L1 lockup unlock height is lower than this bond's minimum unlock height
(define-constant ERR_INVALID_UNLOCK_HEIGHT (err u52))
(define-constant ERR_REWARDS_PAUSED (err u53))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-719)
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2074-2111)
```text
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
```
