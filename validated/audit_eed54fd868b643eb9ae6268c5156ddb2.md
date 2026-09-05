### Title
Reused/spent L1 BTC lockup proofs can be re-submitted to `register-for-bond`, crediting bond shares for sats that are no longer locked - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`register-for-bond`'s L1 lockup path (`verify-l1-lockups` → `validate-l1-lockup`) only proves that a Bitcoin output *existed* at a given block height and paid to the expected timelock script. It never checks whether that output has since been spent, and it never records the outpoint in any contract-persisted "used" set. The only dedup (`seen-outpoints`) is a local accumulator that is reset at the start of every call, so it prevents reusing an outpoint *within one transaction* but does nothing to prevent reusing the exact same historical merkle-proof across multiple, separate `register-for-bond` calls.

### Finding Description
`verify-l1-lockups` [1](#0-0)  folds over the caller-supplied list of Bitcoin outputs via `validate-l1-lockup`, which:
- verifies the block header [2](#0-1) 
- verifies a Merkle inclusion proof of the transaction (or the single-tx shortcut) [3](#0-2) 
- checks the output's scriptPubKey/amount match the expected timelock script for `tx-sender` [4](#0-3) 
- dedups only against `seen-outpoints`, a list initialized fresh for this call [5](#0-4) [6](#0-5) 

Nowhere in `pox-5.clar` is there a persistent map (e.g. `used-l1-lockup-outpoints`) that records an outpoint as consumed once it has been used to credit `sats-total` in a successful `register-for-bond` call. Once a staker's bond period ends (or after they call `announce-l1-early-exit`, which explicitly permits withdrawing/sweeping the physical BTC via the OP_ELSE branch of the timelock script while merely zeroing the in-contract `amount-sats` bookkeeping [7](#0-6) ), the *same* historical proof — the same `tx`, `header`, `leaf-hashes`, `output-index` — remains fully valid input to `validate-l1-lockup`: the contract has no way to check that the underlying BTC output has since been spent. The staker can call `register-for-bond` again for a later, non-overlapping bond, using the exact same proof to be credited `sats-total` sats of bond shares and signer weight, even though the BTC has already left the timelock and is no longer encumbering anything.

This is the direct analog of "burned NFT reminted": the L1 lockup outpoint is meant to function as a single-use bearer proof of currently-locked collateral (analogous to a token ID), but the contract never marks it "burned"/consumed once its collateral is withdrawn, so it can be "reminted" (resubmitted) to mint fresh bond-share credit.

### Impact Explanation
This lets a staker retain signer/bond weight (and the associated reward eligibility) backed by sats that are no longer actually locked on Bitcoin, i.e., "sats credited by an L1 proof that were never locked on Bitcoin" at the time of crediting for the new bond. This directly inflates a signer's/staker's counted stake beyond their real collateral, which can distort reward distribution and signing-weight allocation in `pox-5` without any corresponding BTC actually being locked — a form of unbacked stake creation.

### Likelihood Explanation
The attack requires only actions available to any ordinary staker: create one legitimate L1 timelock, register for a bond, later call `announce-l1-early-exit` (or simply let the bond expire) and physically sweep/spend the BTC via the OP_ELSE early-exit branch, then re-submit the original (still cryptographically valid) merkle proof of the *original* locking transaction to a subsequent `register-for-bond` call for a new, non-overlapping bond. No cooperation from the bond admin, a miner, or another user's key is needed.

### Recommendation
Persist consumed outpoints across calls (e.g., a `map` keyed by `{ txid, output-index }` set the first time a proof is successfully applied in `validate-l1-lockup`/`register-for-bond`), and reject any `register-for-bond` call whose L1 lockup list references an outpoint already marked used, regardless of whether the previous bond membership has since ended or been announced for early exit.

### Proof of Concept
1. Staker locks `S` sats into the canonical P2WSH keyed to their principal and calls `register-for-bond` for bond `N` with a valid Merkle proof of the lockup transaction; `sats-total = S` is credited, `is-l1-lock: true`.
2. Staker calls `announce-l1-early-exit`, which zeroes `amount-sats` for bond `N` in-contract, and independently sweeps the physical BTC out of the P2WSH via the OP_ELSE branch on Bitcoin (per `check_pox_5_register_for_bond_l1_early_unlock_lifecycle`'s documented flow) [8](#0-7) .
3. Once bond `N`'s term/overlap window permits, staker calls `register-for-bond` again for a later bond `M`, supplying the exact same `tx`/`header`/`leaf-hashes`/`output-index` used in step 1.
4. `validate-l1-lockup` re-verifies successfully (the proof only attests to historical inclusion, not current UTXO spent-state), `sats-total = S` is credited again for bond `M`, even though the sats were already withdrawn in step 2 and are no longer locked anywhere on Bitcoin.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1196-1256)
```text
(define-public (announce-l1-early-exit
        (staker principal)
        (old-signer-manager <signer-manager-trait>)
    )
    (let (
            (old-signer (contract-of old-signer-manager))
            (membership (unwrap! (get-bond-membership staker) ERR_NOT_BOND_PARTICIPANT))
            (bond-index (get bond-index membership))
            (signer (get signer membership))
            (current-cycle (current-pox-reward-cycle))
            (bond-start-cycle (bond-period-to-reward-cycle bond-index))
            (bond-end-cycle (bond-period-to-reward-cycle (+ bond-index u6)))
            (current-total-staked (get-total-sbtc-staked-for-bond bond-index))
            (first-changed-reward-cycle (clamp current-cycle bond-start-cycle bond-end-cycle))
            (amount-sats (get amount-sats membership))
        )
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))

        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Only the staker themselves can announce their L1 early exit.
        ;; Calling via other contracts is not allowed.
        (asserts!
            (and (is-eq contract-caller tx-sender) (is-eq contract-caller staker))
            ERR_UNAUTHORIZED
        )
        (asserts! (get is-l1-lock membership) ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK)
        (asserts! (is-eq old-signer signer) ERR_INVALID_OLD_SIGNER_MANAGER)
        (asserts! (not (has-announced-l1-early-exit bond-index staker))
            ERR_L1_EARLY_EXIT_ALREADY_ANNOUNCED
        )

        (try! (unstake-sats-from-bond-cycles staker bond-index
            first-changed-reward-cycle
            (- bond-end-cycle first-changed-reward-cycle) amount-sats u0
        ))

        (map-set protocol-bond-memberships staker
            (merge membership { amount-sats: u0 })
        )
        (map-set protocol-bonds-total-staked bond-index
            (- current-total-staked amount-sats)
        )
        (map-set protocol-bond-l1-early-exit-announced {
            bond-index: bond-index,
            staker: staker,
        }
            true
        )
        (let ((result {
                staker: staker,
                signer: signer,
                bond-index: bond-index,
                amount-sats-released: amount-sats,
            }))
            (print (merge { topic: "announce-l1-early-exit" } result))
            (ok result)
        )
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2057-2091)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2092-2103)
```text
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

**File:** stacks-node/src/tests/pox_5_integrations.rs (L2386-2428)
```rust
#[test]
#[ignore]
/// Verify the OP_ELSE (early-exit) branch of pox-5's L1 lockup script is
/// only spendable when the caller reveals the staker-principal preimage and
/// supplies valid early-unlock and staker signatures.
///
/// `construct-lockup-script`'s OP_ELSE branch is
/// `OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <early-unlock-bytes>`,
/// followed (after OP_ENDIF) by the shared `OP_VERIFY <staker-unlock-bytes>` tail.
/// `<H>` is `sha256(sha256(to-consensus-buff? staker))`, so spending the
/// early-exit branch requires revealing the 32-byte
/// `sha256(to-consensus-buff? staker)` preimage.
///
/// This test demonstrates the realistic script shapes:
///
///   - `staker-unlock-bytes = <unlock_pk> OP_CHECKSIG` (35 bytes, ends 0xac)
///   - `early-unlock-bytes  = <early_pk>  OP_CHECKSIG` (35 bytes, ends 0xac)
///   - Lock 1_000_000 sats into the canonical timelock P2WSH and
///     `register-for-bond` with the lockup tuple.
///
/// The test also accrues rewards, announces the early exit, claims signer
/// rewards, then asserts that `announce-l1-early-exit` did not erase the
/// staker's already accrued rewards.
///
/// All five sweep attempts run *before* `unlock-burn-height`, so the
/// OP_IF branch is unavailable (its CLTV would fail) and the only path
/// the BTC can move is the OP_ELSE branch:
///
///   1. Both sigs from random keys (correct preimage) → mempool rejects
///      (the early-unlock CHECKSIG's OP_VERIFY or the closing CHECKSIG
///      returns false).
///   2. Only the owner sig (early sig from a random key, correct preimage)
///      → rejects: the early-unlock CHECKSIG result fails the shared
///      OP_VERIFY.
///   3. Only the early sig (owner sig from a random key, correct preimage)
///      → rejects: the closing OP_CHECKSIG returns false.
///   4. Both sigs correct, but a wrong (still 32-byte) principal preimage
///      → rejects: `OP_SHA256 <H> OP_EQUALVERIFY` fails before the
///      CHECKSIGs run.
///   5. Both sigs from the correct keys, correct preimage, branch flag
///      empty (selects OP_ELSE) → confirms; the BTC moves to a
///      bondholder-controlled address before the timelock matures.
fn check_pox_5_register_for_bond_l1_early_unlock_lifecycle() {
```
