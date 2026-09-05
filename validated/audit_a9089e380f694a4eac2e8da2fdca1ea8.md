### Title
Reusable L1 BTC-lockup proofs let a staker double-count the same Bitcoin collateral across multiple bond registrations - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond`'s L1 path credits `sats-total` STX-bond collateral to a staker based solely on a Bitcoin merkle/header proof that a specific `(txid, output-index)` UTXO was once created with the correct time-locked script [1](#0-0) . The only duplicate-protection is a `seen-outpoints` list that is built fresh inside a single `fold` over `(get outputs lockups)` for that one call [2](#0-1) ; there is no contract-level map persisting which outpoints have already been consumed as collateral across separate transactions/bonds. A staker can therefore present the exact same historical L1 lockup proof again in a later, non-overlapping `register-for-bond` call to be credited the same sats a second (or Nth) time.

### Finding Description
`verify-l1-lockups` reduces a list of Bitcoin outputs into a `sum` of sats, checking per-output validity (script match, amount match, block header/merkle proof, and de-duplication *within this call only* via `seen-outpoints`) [3](#0-2) . Nothing in `register-for-bond` records that a given `(txid, output-index)` has already been used to justify a bond membership; the accumulator (and its `seen-outpoints`) is discarded after the call returns [4](#0-3) .

The only correctness check tying the proof to a specific bond is that the output's committed `unlock-burn-height` must be `>= (get-bond-l1-unlock-height bond-index)` for the *bond currently being registered for* [5](#0-4) . Because the staker freely chooses `unlock-burn-height` when constructing the original Bitcoin timelock script (it is an input to `construct-lockup-output-script`), they can pick a height far enough in the future to satisfy this "minimum" requirement for many subsequent bond periods, not just the one they initially registered for.

The membership-overlap guard `bond-overlaps-new-position?` only prevents *concurrently overlapping* bonds for the same staker [6](#0-5) ; it does nothing to prevent the staker from rolling out of bond N and later registering for bond N+k (non-overlapping) while re-submitting the identical Bitcoin lockup proof used for bond N. Since a single, one-time BTC lock underwrites unlimited sequential `register-for-bond` calls, the same BTC collateral is double- (or N-times-) counted as backing for multiple, distinct STX bond memberships that the pox-5 accounting (`protocol-bond-memberships`, `protocol-bonds-total-staked`, per-cycle share totals) treats as independently-collateralized commitments [7](#0-6) .

This breaks the equality the L1 path is meant to guarantee: "1 unit of `amount-sats` credited to a bond membership ⇔ 1 unit of BTC currently proven locked on Bitcoin for that specific bond term." With reuse, N bonds can each show `amount-sats` backed by the same underlying (and possibly already-unlocked/spent) BTC output.

### Impact Explanation
This is a double-counting of a BTC-collateral commitment: the same locked (or since-withdrawn) satoshis are used to justify signer weight/reward eligibility and bond membership for more than one bond term, without any additional BTC ever being locked. Per the rules this maps to Critical ("double-counting a commitment or reward") — reward slots/signing weight backed by the L1 path exceed what is actually locked on Bitcoin, since a single BTC lockup can retroactively/prospectively back multiple non-overlapping bonds.

### Likelihood Explanation
Exploitation requires only an allowlisted staker (an ordinary, unprivileged pox-5 participant) to: (1) lock BTC once with a `staker-unlock-bytes`/timelock committing a distant `unlock-burn-height`, (2) call `register-for-bond` for an early bond using that proof, (3) let/force the bond to end or roll over, and (4) call `register-for-bond` again for a later, non-overlapping bond index, resubmitting the identical `(tx, output-index, header, leaf-hashes, ...)` tuple. No admin, signer, or other user's key is needed, and the merkle/header verification passes because it is genuinely the same, previously-valid Bitcoin transaction.

### Recommendation
Persist consumed L1 outpoints in a durable map (e.g. `(define-map used-l1-outpoints {txid: (buff 32), output-index: uint} bool)`), check and set it inside `validate-l1-lockup`/`verify-l1-lockups`, and never delete/clear entries so a given Bitcoin UTXO can back at most one bond membership over its lifetime (or at minimum, only be reusable if the contract can prove the underlying Bitcoin output remains unspent, which pox-5 currently cannot verify at all from an inclusion proof alone).

### Proof of Concept
1. Staker `S` builds a Bitcoin lockup output `O = (txid, output-index)` scripted via `construct-lockup-output-script(S, H_far, stakerUnlockBytes, earlyUnlockBytes)` with `H_far` chosen larger than `get-bond-l1-unlock-height` for several future bond indices.
2. `S` calls `register-for-bond(bond-index=0, ..., btc-lockup=(ok {outputs: [O], ...}))`. `verify-l1-lockups` validates `O` and credits `sats-total = amount(O)`; `S` becomes a member of bond 0 with `amount-sats: sats-total` [8](#0-7) .
3. Bond 0 completes (or `S` exits within its rollover window).
4. `S` calls `register-for-bond(bond-index=6, ..., btc-lockup=(ok {outputs: [O], ...}))` submitting the **same** `O` again. Because `unlock-burn-height` of `O` (`H_far`) still satisfies `get-bond-l1-unlock-height(6)`, and no persistent record blocks reuse of `O`, `verify-l1-lockups` again returns `sats-total`, and `S` is credited `amount-sats: sats-total` a second time for bond 6 — backed by the exact same, single Bitcoin lockup.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-676)
```text
    (let (
            (signer (contract-of signer-manager))
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
```

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-801)
```text
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
        ;; A roll-over from an ending bond ADDS the new bond's shares but does
        ;; NOT tear down the old bond's per-cycle shares/delegation (unlike
        ;; `update-bond-registration`, which removes then re-adds).
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            BOND_LENGTH_CYCLES sats-total
        ))
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
