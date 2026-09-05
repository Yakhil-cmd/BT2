### Title
Reused Bitcoin Lockup Outpoint Can Credit the Same L1 BTC to Multiple pox-5 Bonds - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond` in `pox-5.clar` accepts an L1 Bitcoin timelock proof (`verify-l1-lockups` → `validate-l1-lockup`) to credit `sats-total` toward a protocol bond without moving any sBTC into the contract. The only replay protection for a given Bitcoin outpoint (`txid`, `output-index`) is a `seen-outpoints` list that is built and checked *within the fold call of a single transaction* — it is never persisted to contract state. Nothing prevents the same on-chain lockup output from being submitted again in a later, independent `register-for-bond` call (for the same or a different `bond-index`), crediting `amount-sats` a second time even though no additional BTC was locked. [1](#0-0) [2](#0-1) 

### Finding Description
`verify-l1-lockups` folds over up to 10 `lockup` entries, and `validate-l1-lockup` checks per-entry validity: the timelock script matches the staker's derived script, the claimed amount matches the parsed Bitcoin transaction output, the block header/merkle proof are valid, and the outpoint has not already appeared *earlier in the same list* (`seen-outpoints`): [3](#0-2) 

The accumulator (`seen-outpoints`, `sum`, etc.) is a local value threaded through `fold`; it is discarded once `verify-l1-lockups` returns. There is no map such as `used-lockup-outpoints` (or similar) anywhere in `pox-5.clar` that records an outpoint as consumed across transactions — searches of the contract's map declarations and register-for-bond flow show no such persisted tracking.

Consequently, `sats-total` returned by `verify-l1-lockups` is only unique *within one call*. A staker can:
1. Call `register-for-bond` once with a real L1 lockup proof for outpoint `O` (amount `A` sats), locking their real BTC and being credited `A` sats toward `bond-index=0`.
2. Later call `register-for-bond` again (e.g., for `bond-index=1`, or after unwinding/re-registering into a different bond, subject to the overlap/rollover checks) submitting the *same* outpoint `O` again. `validate-l1-lockup` re-validates the same on-chain proof (still true — the Bitcoin output still exists and is unchanged) and credits `A` sats again.

This breaks the intended equality "sats credited via L1 proof == sats actually locked on Bitcoin, once." The result is a double-counted sBTC-equivalent stake position: `protocol-bonds-total-staked`, `total-shares-staked-for-cycle`, and the staker's own bond share (`amount-sats` in `protocol-bond-memberships`) are inflated relative to the single real BTC lockup, without any corresponding increase in locked STX being required beyond what the (bounded) `min-ustx-for-sats-amount` check demands for the new registration. [4](#0-3) [5](#0-4) 

### Impact Explanation
Bond reward calculations (`bondTargetYieldPerCalculation`, `calculateRewards`) pay sBTC in proportion to `amount-sats` share of a bond's total staked sats. Doubling the credited sats for an unchanged real BTC lockup lets an attacker capture reward share/signer weight/slots that were never backed by additional locked Bitcoin — this is a double-counted commitment (per the rules: "High - ... signing weight or reward slots exceeding locked value"), and if repeated across enough bond registrations, could scale toward unbacked sBTC reward payouts, which the rules classify as Critical.

### Likelihood Explanation
Exploitation requires only a legitimate, one-time real BTC timelock (the attacker's own stake) and multiple `register-for-bond` calls reusing the same already-validated proof data across different bonds/registrations. No signer, admin, or bond-pause privilege is required — an ordinary staker with a normal L1 lockup can attempt this. The rollover/overlap guard (`bond-overlaps-new-position?`) restricts *when* a second registration is allowed but does not tie the outpoint itself to a single credit, so a staker rolling into or opening a second bond in a non-overlapping window can resubmit the same proof.

### Recommendation
Persist consumed L1 outpoints in a dedicated map (e.g., `(define-map used-l1-lockup-outpoints { txid: (buff 32), output-index: uint } bool)`), and have `validate-l1-lockup` (or `verify-l1-lockups`) check-and-set that map so any outpoint can only ever be credited once across the contract's lifetime, not merely once per call.

### Proof of Concept
1. Staker constructs a real Bitcoin timelock output `O` = (`txid`, `output-index`) locking `A` sats to the pox-5 lockup script, with a valid Merkle/header proof.
2. Staker calls `register-for-bond(bond-index=0, ..., btc-lockup=(ok {outputs: [O], ...}))`. `verify-l1-lockups` validates `O` and credits `sats-total = A`; `protocol-bond-memberships` records `amount-sats: A`, `is-l1-lock: true`.
3. In a later reward cycle (after the necessary overlap/rollover window), staker calls `register-for-bond` again for a non-overlapping `bond-index`, submitting the *same* `O` in the `outputs` list. Because `seen-outpoints` is only checked within the current fold and there is no persisted record of `O`, `validate-l1-lockup` re-validates it successfully (the Bitcoin chain state has not changed) and credits `A` sats a second time.
4. `protocol-bonds-total-staked` for the new bond and the staker's own `amount-sats` membership now reflect `A` sats of "locked BTC" that corresponds to the same single, un-duplicated BTC lockup, doubling the staker's counted collateral/reward share without any new BTC being locked.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-708)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L782-801)
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2065-2113)
```text
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
