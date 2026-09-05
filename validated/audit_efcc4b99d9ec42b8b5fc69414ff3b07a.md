### Title
`register-for-bond`'s L1 path credits `sats-total` from a Bitcoin merkle proof that never checks the timelock hasn't already expired/been spent - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`verify-l1-lockups` / `validate-l1-lockup` in `pox-5.clar` only prove that a Bitcoin output with the correct staker-timelock script, amount, and `unlock-burn-height` was mined into a real historical block; they never check that `unlock-burn-height` is still in the future relative to `burn-block-height`, and there is no persisted, cross-transaction record of consumed outpoints. An attacker can therefore replay the merkle proof of a legitimately-locked-and-since-unlocked (and already withdrawn) Bitcoin output to mint STX-locking/signing-weight credit for BTC that is no longer custodied anywhere.

### Finding Description
The claimed equality is: `sats-total` credited in `protocol-bond-memberships` (`amount-sats`) should equal the sats that are *currently* locked and unspent in a confirmed Bitcoin timelock output committed to `tx-sender`.

Call path: `register-for-bond` [1](#0-0)  dispatches to `verify-l1-lockups` [2](#0-1) , which folds `validate-l1-lockup` over each proof entry [3](#0-2) .

`validate-l1-lockup` checks, per output:
- `unlock-burn-height >= minimum-unlock-height` (the bond's required minimum) and `< BITCOIN_LOCKTIME_THRESHOLD` (just distinguishing block-height vs. timestamp locktime encoding) [4](#0-3) .
- The output's script matches the expected staker timelock script and amount [5](#0-4) .
- The outpoint hasn't been seen already *within this same call* via a **local, ephemeral** `seen-outpoints` accumulator capped at 10 entries, produced fresh each call and never persisted to contract storage [6](#0-5) [7](#0-6) .
- The header is a legitimate historical burn header via `verify-block-header`, and a merkle proof ties the tx into that block [8](#0-7) .

Nowhere in this fold, nor anywhere else in `pox-5.clar`, is `unlock-burn-height` compared against the current `burn-block-height`, and there is no persisted map (e.g. a `used-l1-outpoints` map) recording outpoints consumed by *previous, separate* `register-for-bond` calls. The only cross-call state that exists for L1 locks is `protocol-bond-l1-early-exit-announced`, which is orthogonal (an accounting-only flag set by `announce-l1-early-exit`, itself unrelated to actual L1 spend status) [9](#0-8) .

Exploit flow:
1. Attacker legitimately locks BTC in a timelock script that satisfies the staker-script derivation, with an `unlock-burn-height` that meets the bond's minimum requirement.
2. Once the real Bitcoin chain passes that `unlock-burn-height`, the attacker (holding the private key) spends the output back to themselves on L1 — the BTC is no longer locked anywhere.
3. Attacker keeps the original locking transaction, its merkle path, and the block header used to mine it.
4. Attacker calls `register-for-bond` again (a new bond period, or after the original membership's bond term has fully rolled over) supplying the *same, stale* proof as `btc-lockup`. `validate-l1-lockup` re-validates script/amount/height/merkle-inclusion — all of which are still true historically — and the local `seen-outpoints` dedup does not block a fresh call.
5. `sats-total` is credited as if that BTC is still locked, `amount-ustx` is derived from it via `min-ustx-for-sats-amount`, and `map-set protocol-bond-memberships` records `is-l1-lock: true, amount-sats: sats-total` with no BTC actually custodied [10](#0-9) .

None of the existing guards (`verify-not-prepare-phase`, `check-pox-lock-period`-style allowance checks, `verify-signer-key-grant`, the `<=` allowance guard, `bond-overlaps-new-position?`) validate current L1 UTXO status; they all operate purely on the Stacks-side accounting. The `<= sats-total allowance` guard only bounds the total to the allowlisted cap, it does not verify the sats are presently locked.

### Impact Explanation
This mints unbacked STX-locking/signing weight and reward eligibility: the staker obtains a `protocol-bond-memberships` entry with `is-l1-lock: true` and `amount-sats: sats-total` backed by zero actual sBTC/BTC custody (L1 lock path never moves sBTC into the contract — `new-sbtc` is `u0` on the L1 branch). This grants signer-cycle delegation via `add-staker-to-signer-cycles`/`add-staker-to-bond-cycles`, and reward eligibility computed off `amount-sats`/`amount-ustx`, all against phantom collateral. This matches the Critical category: "unbacked minting of locked STX ... signing weight or reward slots exceeding locked value," repeatable for every stale/expired timelock proof the attacker retains, and for every future bond period as long as the bond's minimum-unlock-height requirement is satisfiable by an already-expired historical timelock.

### Likelihood Explanation
Preconditions: attacker must have legitimately created at least one qualifying L1 timelock in the past (any unprivileged staker can do this themselves), and it must have already unlocked (or the attacker forges/salvages proof material for an output whose `unlock-burn-height` is in the past relative to now but still `>=` the bond's minimum). No privileged role, no compromised dependency, no reentrancy is needed — only correct crafting of the `btc-lockup` argument's `outputs` list with real historical merkle data. This is fully attacker-controlled and repeatable across bond periods/registrations since the anti-replay set is per-call and non-persistent.

### Recommendation
1. Add a persisted, contract-level `used-l1-outpoints` map (or similarly durable set) keyed by `{txid, output-index}` that is checked and updated on every successful `validate-l1-lockup`, rejecting any outpoint that has ever been credited before, across all calls and all bond periods.
2. Additionally require `unlock-burn-height > burn-block-height` (or some equivalent "still time-locked as of now" check) at validation time, so a proof cannot be accepted for an output whose timelock has already expired (and thus is spendable/spent by the key holder).

### Proof of Concept
Rust integration test plan (extends `stacks-node/src/tests/pox_5_integrations.rs`):
1. Boot a simnet/naka chain; create and confirm a valid staker timelock output at height `H` with `unlock-burn-height = U` satisfying the bond's minimum.
2. Advance the chain past `U`; have the "attacker" spend the output back to their own address in a normal Bitcoin transaction (still holding the private key, simulating "already spent but still controlled").
3. Capture the original locking tx's raw bytes, merkle path, and block header from step 1.
4. Call `register-for-bond` with this stale proof as `btc-lockup` for a *new* bond period whose `bond-period-to-burn-height` and `get-bond-l1-unlock-height` are compatible with `U`.
5. Assert BEFORE: sats actually locked+unspent on the real Bitcoin timelock for this staker = `0` (already withdrawn).
6. Assert AFTER: `get-bond-membership`/`protocol-bond-memberships` for the staker shows `is-l1-lock: true, amount-sats: <original sats>` and `protocol-bonds-total-staked` increased by that amount — i.e., `sats-total credited != sats currently locked on L1 (0)`, confirming the broken equality and unbacked signing weight/reward eligibility minted.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L642-676)
```text
(define-public (register-for-bond
        (bond-index uint)
        (signer-manager <signer-manager-trait>)
        (amount-ustx uint)
        ;; Their BTC lockup info. If the response is `ok`, then
        ;; this is a list of outputs corresponding to their timelocks.
        ;; If the response is `err`, this is the amount of sBTC (in sats)
        ;; that they want to lock.
        (btc-lockup (response {
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
        }
            uint
        ))
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-792)
```text
        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
            amount-sats: sats-total,
        })
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1198-1246)
```text
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
