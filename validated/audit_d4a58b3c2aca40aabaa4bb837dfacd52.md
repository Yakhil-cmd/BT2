### Title
Reused Bitcoin L1 lockup outpoints can be credited multiple times across bonds - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond` in pox-5 credits stakers with "sats" of BTC lockup by validating a Bitcoin merkle-proof and P2WSH timelock script via `verify-l1-lockups` / `validate-l1-lockup` [1](#0-0) . The only duplicate-detection mechanism is a `seen-outpoints` list that is initialized fresh on every call and only checked within the outputs of that single call [2](#0-1) [3](#0-2) . There is no contract-wide persistent map recording which `(txid, output-index)` outpoints have already been consumed by a prior `register-for-bond` call.

### Finding Description
`validate-l1-lockup` verifies: the script matches the staker's timelock script, the unlock height, the merkle proof/block header, and that the outpoint is not duplicated *within the same call's `outputs` list* [4](#0-3) . It never checks the outpoint against state persisted from previous, already-processed `register-for-bond` transactions. Because the same real Bitcoin lockup transaction/output can be re-submitted as proof in a second (or Nth) `register-for-bond` call — for the same staker across different `bond-index` values, or potentially by different `staker` principals since `construct-lockup-output-script` derives the expected script from the caller's own principal and could coincidentally/adversarially collide depending on script construction — the contract will accept the same physically-locked sats as valid backing multiple times. Each successful call updates `protocol-bond-memberships`, `protocol-bonds-total-staked`, and the staker/signer per-cycle stacked totals with the full `sats-total` [5](#0-4) , so one Bitcoin lock backs multiple bond memberships' worth of on-chain "amount-sats" and STX unlock/reward-slot accounting.

This breaks the equality the protocol relies on: `sum of amount-sats credited across all bond memberships == sats actually and currently locked on Bitcoin`. The Bitcoin-side reserve (the real BTC UTXO) is treated like a spot value that is re-read and re-credited without any check that it has already been "spent" for credit purposes — directly analogous to the reported bug class where a manipulable/reusable external value source is trusted without a running commitment check.

### Impact Explanation
This is a Critical-class analog: double-counting a commitment (sats credited to more than one bond/stake without additional BTC being locked), which can inflate a staker's/signer's effective stacked weight (reward slots, signing weight) beyond what is actually collateralized on Bitcoin, and can be used to satisfy `min-ustx-for-sats-amount` STX-matching requirements for more STX than the real BTC backing justifies.

### Likelihood Explanation
Reachable by any unprivileged staker who is allow-listed for more than one bond period (the allow-list and bond mechanics appear designed for stakers to be re-added/roll over across `bond-index`, cf. `existing-membership`/roll-over logic at [6](#0-5) ), requiring no special privileges beyond calling `register-for-bond` twice with the same lockup proof for two different `bond-index` values.

### Recommendation
Persist a contract-wide map (e.g., `used-l1-lockup-outpoints: {txid, output-index} -> bool` or `-> bond-index`) that is checked and set in `validate-l1-lockup`/`verify-l1-lockups`, independent of the per-call `seen-outpoints` accumulator, so a given Bitcoin outpoint can only ever back one active bond/stake for its lock duration.

### Proof of Concept
1. Staker generates a valid Bitcoin L1 lockup transaction/output and unlock-height per `construct-lockup-output-script`.
2. Staker calls `register-for-bond` for `bond-index = A`, submitting the lockup proof; `validate-l1-lockup` accepts it, credits `sats-total` to bond A's totals via `protocol-bonds-total-staked` and `staker-shares-staked-for-cycle` [5](#0-4) .
3. Staker (while eligible/allow-listed) calls `register-for-bond` again for `bond-index = B`, submitting the exact same `tx`/`output-index`/`header`/merkle-proof. Because `seen-outpoints` is reset per call, `validate-l1-lockup` passes all checks again and credits the same sats a second time to bond B.
4. No mechanism in the reviewed contract flags the reused outpoint, resulting in the same Bitcoin lock backing two separate bond memberships' `amount-sats` totals.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L677-708)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L781-805)
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2057-2103)
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
```
