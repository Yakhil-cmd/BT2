### Title
Reusable L1 Bitcoin lockup proof lets a staker double-count one BTC lockup across multiple `register-for-bond` calls, crediting sats/shares in `pox-5.clar` that were only ever locked once - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond`'s L1 path verifies a Bitcoin lockup proof via `verify-l1-lockups` → `validate-l1-lockup`, but the only duplicate-prevention mechanism (`seen-outpoints`) is scoped to the single call's `fold` accumulator. There is no contract-level, persistent map recording which Bitcoin `(txid, output-index)` outpoints have already been credited to a bond. A staker can therefore submit the exact same valid Bitcoin lockup proof to `register-for-bond` more than once (for different, non-overlapping `bond-index` values, or after exiting/rolling out of the previous bond), each time getting `sats-total` credited into `protocol-bonds-total-staked`, `staker-shares-staked-for-cycle`, and `signer-shares-staked-for-cycle` — without ever locking any additional BTC.

### Finding Description
`verify-l1-lockups` (`stackslib/src/chainstate/stacks/boot/pox-5.clar:1984-2019`) verifies the Bitcoin merkle proof, script hash, and amount for each output, and folds over the outputs while tracking `seen-outpoints` only to prevent duplicates *within the same call* [1](#0-0) . The core check inside `validate-l1-lockup` only asserts that the outpoint hasn't already appeared earlier in the *current* fold (`is-none (index-of? seen-outpoints outpoint)`), not that it has never been used in any prior transaction [2](#0-1) .

`register-for-bond` calls `verify-l1-lockups` fresh on every invocation and treats its returned `sats-total` as newly-locked collateral: it adds `sats-total` to `protocol-bonds-total-staked` and calls `add-staker-to-bond-cycles`/`add-staker-to-signer-cycles` with that amount, crediting shares for reward distribution [3](#0-2) . Because the script-hash check (`construct-lockup-output-script`) only binds the staker principal, `unlock-burn-height`, and the subscripts — not the specific `bond-index` or a global nonce — the same real UTXO satisfies the proof for any bond whose `minimum-unlock-height` (`get-bond-l1-unlock-height`) is at or below the UTXO's actual claimed unlock height [4](#0-3) .

`bond-overlaps-new-position?` only prevents *concurrently overlapping* bond terms for the same staker, not reuse of the same BTC proof across sequential (non-overlapping) bond terms. Once bond N ends (or the staker exits/rolls over), the staker can call `register-for-bond` again for bond N+k, resubmitting the identical `tx`/`header`/`leaf-hashes`/`output-index` payload. `verify-l1-lockups` will re-validate it successfully (it is a real, valid Bitcoin proof) and mint a fresh `sats-total` credit for the new bond period, even though the underlying BTC was never additionally locked or moved.

This breaks the equality "shares credited by an L1 proof == BTC actually locked on Bitcoin for that period," letting one lockup be double- (or N-times-) counted across sequential bond registrations.

### Impact Explanation
Signer/staker `sats` shares drive reward computation in `calculate-rewards`/`get-rewards`/target-rate reward math for bond periods. Inflating `sats-total` for a bond period the attacker is not actually backing with additional BTC lets the staker (and their signer) claim sBTC rewards proportional to collateral that doesn't exist for that period, and inflates `protocol-bonds-total-staked`/signer-set weighting used for reward-slot eligibility. This is a double-counting of a commitment leading to unbacked reward accrual — meeting the Critical/High bar ("double-counting a commitment or reward," "signing weight or reward slots exceeding locked value").

### Likelihood Explanation
The attack requires only a single real (but modest) BTC lockup and no privileged role — any allow-listed staker with a genuine BTC UTXO can replay the exact same proof bytes into a later `register-for-bond` call once their earlier bond term ends. No signer/admin cooperation or bond-pause access is needed, and the same lockup metadata (`tx`, `header`, `leaf-hashes`, `output-index`) can be reused verbatim since Bitcoin proofs are permanently valid once mined.

### Recommendation
Add a persistent map (e.g., `used-l1-outpoints: {txid: (buff 32), output-index: uint} -> bool`) and have `validate-l1-lockup` `map-insert` each outpoint before accepting it, returning `ERR_DUPLICATE_LOCKUP_OUTPOINT` (or a dedicated error) if the outpoint was already claimed in any prior call — not just within the current fold. Alternatively, bind the credited amount to a one-time claim keyed by the outpoint and `staker`, independent of `bond-index`, so a single UTXO can never back more than one bond's shares concurrently or sequentially.

### Proof of Concept
1. Staker Alice is allow-listed for bond-index 0 and bond-index 6 (non-overlapping terms).
2. Alice locks 1,000,000 sats on Bitcoin with the `construct-lockup-script` for `staker = alice`, `unlock-burn-height = H` (H covers both bond windows).
3. Alice calls `register-for-bond(bond-index: 0, ..., btc-lockup: ok({outputs: [proof], staker-unlock-bytes}))`. `verify-l1-lockups` succeeds, crediting 1,000,000 sats of shares to bond 0 for Alice/her signer.
4. Bond 0's term ends; Alice's membership is inactive/rolled out.
5. Alice calls `register-for-bond(bond-index: 6, ..., btc-lockup: ok({outputs: [same proof], staker-unlock-bytes}))` — identical `tx`, `header`, `leaf-hashes`, `output-index`. `verify-l1-lockups` re-validates the same real Bitcoin output successfully (no global outpoint registry blocks it) and again credits 1,000,000 sats of shares to bond 6.
6. Alice has now been credited 2,000,000 sats of bond shares (and corresponding signer weight/reward eligibility) from a single 1,000,000-sat BTC lockup — confirmed by inspecting `protocol-bonds-total-staked` for both bond-index 0 and 6, and `get-earned`/reward accrual after `calculate-rewards` runs for bond 6.

### Citations

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2057-2076)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2086-2088)
```text
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```
