### Title
Reusable L1 Bitcoin lockup proofs allow a staker to double-count the same locked BTC across multiple bond registrations - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond` accepts a Bitcoin-lockup proof (`btc-lockup`) and calls `verify-l1-lockups` → `validate-l1-lockup` to credit `sats-total` sats of collateral for a bond. The only duplicate-outpoint protection is a `seen-outpoints` list that is initialized fresh inside the single call's `fold` [1](#0-0) , and is never checked against, or written to, any persistent contract state. Nothing in the contract prevents the exact same Bitcoin transaction output from being presented again in a later, separate `register-for-bond` call to credit `sats-total` a second (or Nth) time.

### Finding Description
`validate-l1-lockup` verifies that a Bitcoin output really exists, has the expected timelock script, the claimed amount, a valid merkle proof, and is not repeated *within the current call's* `seen-outpoints` accumulator: [2](#0-1) 

All of these checks are legitimate, but they are purely local to the fold that runs during one invocation of `register-for-bond`. The `seen-outpoints` list is constructed as `(list)` at the start of `verify-l1-lockups` for every call: [1](#0-0) 

There is no map anywhere in `pox-5.clar` that records "outpoint X has already been used to back a bond" (a `grep` for `define-map` and for outpoint-tracking identifiers over the whole file returns nothing relevant), so once a Bitcoin lockup with a sufficiently distant `unlock-burn-height` has been mined, the staker can supply the identical `(tx, output-index, header, leaf-hashes, ...)` tuple to `register-for-bond` again for a different `bond-index` (or after unstaking/rolling out of the first bond) and it will pass every check again, because the script (`construct-lockup-output-script`) is deterministic given `(staker, unlock-burn-height, staker-unlock-bytes, early-unlock-bytes)` and the merkle/heard checks are re-derivable from public chain data supplied by the caller.

`register-for-bond` uses this unchecked `sats-total` to: cap-check against the staker's per-bond allowance (`asserts! (<= sats-total allowance) ERR_TOO_MUCH_SATS`), record `amount-sats: sats-total` in `protocol-bond-memberships`, and add `sats-total` into `protocol-bonds-total-staked` [3](#0-2) . Because only one membership is tracked per staker (`protocol-bond-memberships tx-sender` is a single-key map) the staker cannot hold two *overlapping* bonds simultaneously, but nothing stops them from sequentially rolling the same physical BTC lockup output into bond after bond, or from re-registering for the same bond concept after an early exit, each time re-crediting the collateral figure that ultimately feeds reward-share calculations (`add-staker-to-bond-cycles`, `protocol-bonds-total-staked`) without ever locking additional BTC.

This is the direct analog of the reported `preallocate` bug: a privileged-looking amount (here, "sats actually locked on L1") is accepted and used to update protocol-wide accounting (`protocol-bonds-total-staked`, reward-share weight) with no check that this specific unit of collateral had not already been consumed/counted elsewhere — the "cap not exceeded" and "already processed" sanity checks that `preallocate` was missing are likewise missing here for L1 lockup outpoints.

### Impact Explanation
This breaks the equality between actual BTC locked on Bitcoin and sats credited inside pox-5's accounting. A staker can repeatedly present the same L1 lockup proof to inflate `protocol-bonds-total-staked` and their own recorded `amount-sats` across multiple bond periods, letting them (a) satisfy `ERR_TOO_MUCH_SATS`/allowance checks with collateral that was already "spent" backing a prior bond, and (b) claim proportional reward share for a bond period their BTC was not actually newly securing. This is "sats credited by an L1 proof that were never locked on Bitcoin" (for the second and subsequent uses) and "double-counting a commitment" against other honest bond participants' reward shares — a Critical-severity issue per the stated impact criteria.

### Likelihood Explanation
Any unprivileged staker who is on a bond's allowlist can trigger this: it requires no admin/bond-admin privilege, just a previously-mined Bitcoin lockup transaction with an `unlock-burn-height` far enough in the future to satisfy `get-bond-l1-unlock-height` for more than one bond period, and re-submitting the identical proof data in a later `register-for-bond` call. Given that L1 timelocks are naturally long-lived (their whole purpose is to remain locked for a while), it is easy for a legitimate lockup to still satisfy the "minimum unlock height" check of a subsequent, later bond.

### Recommendation
Persist consumed L1 outpoints (`txid`, `output-index`) in a contract-level map (e.g. `l1-lockup-outpoints-used`) and `asserts!` that each outpoint has not been previously recorded before crediting `sats-total`, marking it as used as part of the same transaction. Alternatively, bind the credited amount to the bond-index/registration epoch inside the timelock script itself (e.g. hash the bond-index into `construct-lockup-output-script`) so a single Bitcoin lockup can only ever satisfy one specific bond registration.

### Proof of Concept
1. Staker locks `N` sats on Bitcoin into the canonical timelock P2WSH computed via `construct-lockup-output-script(staker, unlock_burn_height, staker_unlock_bytes, early_unlock_bytes)`, with `unlock_burn_height` set far enough in the future to satisfy the `minimum-unlock-height` of two sequential bonds (bond A and bond B).
2. Staker calls `register-for-bond(bond-index=A, ..., btc-lockup=(ok {outputs: [that output], staker-unlock-bytes}))`. `validate-l1-lockup` passes all checks; `sats-total = N` is credited into bond A's `protocol-bond-memberships` and `protocol-bonds-total-staked` [4](#0-3) .
3. Staker exits/rolls out of bond A (or waits for bond A to end so `existing-membership` no longer overlaps).
4. Staker calls `register-for-bond(bond-index=B, ..., btc-lockup=(ok {outputs: [the SAME output], staker-unlock-bytes}))`. Because `seen-outpoints` starts empty for this new call and no persistent map records the outpoint as used, `validate-l1-lockup` passes again and `sats-total = N` is credited a second time into bond B's accounting — from a single, unchanged BTC lockup.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L742-795)
```text

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
