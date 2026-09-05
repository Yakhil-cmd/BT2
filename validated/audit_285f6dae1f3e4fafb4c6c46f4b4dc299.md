# Title
Unbounded replay of a single L1 BTC lockup proof across multiple `register-for-bond` calls lets a staker credit already-spent Bitcoin collateral to new bonds — ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

## Summary
`register-for-bond`'s L1 lockup path (`verify-l1-lockups` → `validate-l1-lockup`) only proves that a Bitcoin transaction output *once existed* with the expected timelock script, amount, and block inclusion. It never checks that the output is still unspent, and there is no persistent, cross-call record of which L1 outpoints have already been consumed — only an in-call `seen-outpoints` list scoped to a single transaction's fold. A staker can therefore resubmit the exact same historical merkle proof for a later, non-overlapping bond period and receive fresh `sats-total` credit even though the real BTC backing it has already matured and been withdrawn on Bitcoin.

## Finding Description
`register-for-bond` computes `sats-total` for the L1 path via: [1](#0-0) 

which calls `verify-l1-lockups`, which folds `validate-l1-lockup` over the caller-supplied outputs: [2](#0-1) 

`validate-l1-lockup` checks: the unlock height is at least the bond's required minimum, the output's script matches the deterministically-constructed timelock script for `(staker, unlock-burn-height, staker-unlock-bytes, early-unlock-bytes)`, the amount matches, the outpoint hasn't been seen *within this call*, the header is valid, and a merkle proof (or single-tx shortcut) ties the tx into that header: [3](#0-2) 

None of these checks reference Bitcoin's current UTXO set — Clarity has no way to query whether an output has since been spent, and the contract does not compensate by tracking used outpoints in a persistent map (`seen-outpoints` is a fresh, per-call accumulator built at line 2013 and discarded after the call returns). The dedup only prevents replay of the same outpoint *inside a single list of ≤10 outputs*, as confirmed by the integration test description: "the per-output dedup inside `validate-l1-lockup` trips before the post-fold sum check." [4](#0-3) 

Because the timelock script's `unlock-burn-height` is fixed at Bitcoin-lock time and can be set arbitrarily far in the future, a staker can create one long-dated L1 timelock, use it to `register-for-bond` for bond `N` (crediting `sats-total` into `protocol-bond-memberships` and `protocol-bonds-total-staked`): [5](#0-4) 

then, once the bond `N` term ends (or once the real Bitcoin timelock matures and the staker actually withdraws/spends the BTC on L1), resubmit the identical `tx`/`header`/`leaf-hashes`/`output-index` proof to `register-for-bond` for a later, non-overlapping bond `N+6` — the `bond-overlaps-new-position?` gate only checks the staker's Stacks-side membership timing, not whether the underlying BTC is still locked. As long as the fixed `unlock-burn-height` embedded in the (already-spent) script still satisfies `get-bond-l1-unlock-height(N+6)`, `validate-l1-lockup` succeeds again and `sats-total` is credited a second time to `protocol-bonds-total-staked` and to the staker's/signer's per-cycle shares, which drive reward-slot weighting (`pox_5_make_signer_set`) and bond reward payouts (`calculate-rewards`).

This breaks the invariant that `protocol-bonds-total-staked` / signer weight must equal BTC actually locked on Bitcoin: the contract's ledger reflects sats that are no longer locked at all.

## Impact Explanation
This is Critical under the stated rubric: "sats credited by an L1 proof that were never locked on Bitcoin" and "double-counting a commitment or reward." The staker gains signer reward-slot weight and sBTC bond-reward eligibility (`get-earned`, `claim-staker-rewards`) proportional to `sats-total` without any real, currently-locked BTC collateral backing the later bond period, diluting or displacing honestly-collateralized signers/stakers and paying rewards against phantom collateral.

## Likelihood Explanation
Reachable by any allow-listed bond participant using only their own transaction data; no privileged role is required. The only precondition is that the original real Bitcoin timelock's chosen `unlock-burn-height` exceeds the `minimum-unlock-height` of a subsequent bond the staker is allow-listed for — a value the staker themselves chose when constructing the lockup script, so they can set it arbitrarily far ahead to enable repeated reuse.

## Recommendation
Persist a global (not per-call) map of consumed L1 outpoints (`{txid, output-index}` → used) that is checked and set inside `validate-l1-lockup`/`verify-l1-lockups` across all `register-for-bond` invocations, so a given Bitcoin output can only ever back one bond credit. Alternatively/additionally, require the staker to prove continued custody (e.g., via a fresh, still-unspent SPV-style proof tied to the specific bond window, or an explicit unlock/re-lock cycle) rather than allowing an old, already-matured timelock proof to be replayed indefinitely.

## Proof of Concept
1. Staker constructs an L1 timelock script for themselves with `unlock-burn-height = H` set far in the future (larger than the `minimum-unlock-height` of several future bonds), and sends BTC to it.
2. Staker calls `register-for-bond` for bond `N` with the resulting `{outputs, staker-unlock-bytes}` proof; `verify-l1-lockups`/`validate-l1-lockup` succeed, crediting `sats-total` sats to bond `N`.
3. After bond `N`'s term (or once real BTC timelock matures), the staker spends/withdraws the real BTC on the Bitcoin chain via `staker-unlock-bytes`.
4. Staker again calls `register-for-bond`, now for a later non-overlapping bond `N+6` (allowed because `bond-overlaps-new-position?` only compares Stacks-side cycle ranges), submitting the identical historical `tx`/`header`/merkle-proof tuple from step 1.
5. `validate-l1-lockup` re-validates successfully (script/amount/header/merkle checks all pass again; `unlock-burn-height = H` still `>= get-bond-l1-unlock-height(N+6)`), crediting `sats-total` again to `protocol-bonds-total-staked` for bond `N+6` even though the real BTC no longer exists as a locked UTXO.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L672-676)
```text
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-805)
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

**File:** stacks-node/src/tests/pox_5_integrations.rs (L1416-1420)
```rust
/// Assertions:
/// - submitting the same lockup outpoint three times in the L1 proof list
///   is rejected with `ERR_DUPLICATE_LOCKUP_OUTPOINT` (u46) — the per-output
///   dedup inside `validate-l1-lockup` trips before the post-fold sum check,
///   and the failure leaves the staker with no bond membership and no STX lock
```
