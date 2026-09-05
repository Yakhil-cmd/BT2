### Title
Stale/reused L1 Bitcoin lockup proof lets a staker double-count sats collateral in `register-for-bond` - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond`'s L1 path credits a staker with `sats-total` uSTX-backing weight purely from a Merkle-proof of a historical Bitcoin transaction output, without ever checking that the referenced UTXO is *still* locked (unspent) at the time of the call. The same historical Bitcoin output can therefore be replayed across multiple, sequential bond registrations to back new bonds, exactly mirroring the external report's bug class ("value credited that was never actually locked/backed"), just applied to the sats side of the STX/sBTC equality instead of a Uniswap price.

### Finding Description
In `register-for-bond`, when the staker chooses the L1 path (`btc-lockup` is `ok`), `sats-total` is computed by `verify-l1-lockups`: [1](#0-0) 

`verify-l1-lockups` folds over the supplied outputs via `validate-l1-lockup`, which checks:
- the output's script matches the staker's expected timelock script (`construct-lockup-output-script`)
- the amount matches
- the block header/merkle proof is valid (i.e., the transaction really happened on Bitcoin at some point)
- `unlock-burn-height >= minimum-unlock-height` for the *new* bond
- no duplicate outpoint *within this single call's list* [2](#0-1) 

None of these checks establish that the UTXO is *currently unspent*. The Clarity contract has no way to query current Bitcoin UTXO-set state (only historical block/tx inclusion), so once a lockup's `unlock-burn-height` has passed, the staker is free to spend the real BTC via the timelock script on Bitcoin, while still holding the exact same historical transaction/proof data. `seen-outpoints` dedup is local to the single `verify-l1-lockups` invocation, not a persistent, contract-wide map, so nothing stops the staker from resubmitting that same transaction/output in a *later* `register-for-bond` call for a new `bond-index` (once their prior bond's term has fully rolled over per `bond-overlaps-new-position?`) and getting `sats-total` credited again: [3](#0-2) [4](#0-3) 

`protocol-bonds-total-staked` and per-cycle staker/signer shares are incremented by `sats-total` with no on-chain corroboration that new BTC is actually locked for this new bond term — the "collateral" is the same, already-withdrawable (or already-withdrawn) satoshis reused indefinitely.

### Impact Explanation
This breaks the core equality that `pox-5` is built to enforce: staked/bonded sats (and the derived `min-ustx-for-sats-amount` STX lock, reward-weight shares, and `protocol-bonds-total-staked` accounting) must correspond to real, currently-locked Bitcoin collateral. A staker can obtain signer/staker reward shares and bond membership for successive bond terms while only ever having locked BTC once (or never re-locking at all after the first term expires), i.e., "signing weight or reward slots exceeding locked value" — explicitly a High-impact class per the scope rules, and arguably Critical since it double-counts a commitment across bond terms with no additional Bitcoin ever locked.

### Likelihood Explanation
Exploitation requires only an unprivileged staker who already completed one legitimate L1 lockup and was allow-listed for a subsequent bond (`protocol-bond-allowances`) — no privileged accounts, oracle, or admin action needed. The only "attack" step is timing: wait until the original UTXO's `unlock-burn-height` passes (which the honest lockup schedule guarantees will eventually happen), then resubmit the same historical proof data to `register-for-bond` for a new bond index.

### Recommendation
Persist consumed L1 outpoints in a durable map (e.g. `map-set used-l1-outpoints {txid, output-index} true`) that is checked and updated across *all* calls to `validate-l1-lockup`/`verify-l1-lockups`, not just within a single call's fold accumulator, so a given Bitcoin output can only ever back one bond registration for its entire lifetime. Alternatively/additionally, require fresh L1 lockup proofs whose `unlock-burn-height` is strictly in the future at verification time (not just `>= minimum-unlock-height` for the new bond), preventing reuse of already-spendable/expired timelocks.

### Proof of Concept
1. Staker Alice completes a legitimate L1 lockup for bond 0 via `register-for-bond(bond-index=0, ..., btc-lockup=ok([output_A]))`; `sats-total` = amount of `output_A`, credited to bond 0.
2. Bond 0's `unlock-burn-height` passes; Alice (holding the unlock key) spends `output_A` on Bitcoin, withdrawing her real BTC.
3. Once allow-listed for bond 6, Alice calls `register-for-bond(bond-index=6, ..., btc-lockup=ok([output_A]))` again, submitting the *same* historical transaction/merkle proof for `output_A`.
4. `validate-l1-lockup` re-validates the (still historically true) merkle proof and script match, and since `seen-outpoints` only tracks duplicates within this call's own output list, `sats-total` for bond 6 is credited the full amount again — with no new BTC ever locked. [5](#0-4)

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L713-719)
```text
        (asserts!
            (>= amount-ustx
                (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
                    (get min-ustx-ratio bond)
                ))
            ERR_INSUFFICIENT_STX
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L782-805)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1938-1979)
```text
;; Move a staker's custodied sBTC from `old-sbtc` to `new-sbtc`, transferring
;; only the net difference: pull the increase from the staker, or refund the
;; decrease. `total-sbtc-staked` is updated by the net change. A registration
;; with no rollover passes `old-sbtc` of `u0`, which transfers the full amount.
;; A no-op when the two are equal.
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
