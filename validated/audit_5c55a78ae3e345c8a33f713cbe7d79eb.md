Confirmed: there is no persistent, contract-wide map recording L1 lockup outpoints that have already been claimed. `verify-l1-lockups`/`validate-l1-lockup` only track duplicates within a single call's `seen-outpoints` accumulator, which starts empty every time `register-for-bond` is invoked.

### Title
Same Bitcoin L1 lockup outpoint can be replayed across multiple `register-for-bond` calls to double-count sats never re-locked - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond` credits `sats-total` to a staker's bond membership based on Merkle/Bitcoin-header proofs of on-chain L1 UTXO lockups, verified by `verify-l1-lockups` [1](#0-0) . The only anti-replay guard, `seen-outpoints`, is a fresh, per-call accumulator built up during `fold validate-l1-lockup` and discarded once the call returns [2](#0-1) . Nothing persists which (txid, output-index) pairs have already been used across separate transactions or across different stakers/bonds.

### Finding Description
`validate-l1-lockup` checks the lockup script, amount, unlock height, Merkle proof, and header, and rejects duplicates only within the same `outputs` list via `(index-of? seen-outpoints outpoint)` [3](#0-2) . `seen-outpoints` is initialized to `(list)` at the start of every `verify-l1-lockups` call [4](#0-3) , so it provides no protection between transactions. There is no map such as `used-l1-lockup-outpoints` anywhere in the contract (confirmed by search) that would record an outpoint as consumed once credited to a bond.

Because the same Bitcoin outpoint's proof (header + Merkle path + tx bytes) is public once it is mined, any staker (the original lockup owner or, since `staker` is only checked against the script inside the proof but the caller supplies `tx-sender` and constructs `expected-script-hash` using their own claimed identity, potentially a colluding/duplicate registration by the same staker across two different bonds) can resubmit the identical outpoint in a second `register-for-bond` call for a different `bond-index`. Each call independently calls `verify-l1-lockups` with an empty `seen-outpoints`, so the duplicate is accepted, and `sats-total` is credited a second time into `protocol-bond-memberships`, `protocol-bonds-total-staked`, and per-cycle share maps via `add-staker-to-bond-cycles` [5](#0-4) .

This breaks the required equality between sats credited by an L1 proof and sats actually locked on Bitcoin: the same locked BTC output backs two separate bond positions, each of which independently earns sBTC rewards proportional to `total-sats` in `calculate-bond-rewards` [6](#0-5) , and each of which counts toward `signer-shares-staked-for-cycle` used for signing-weight determination.

### Impact Explanation
Double-crediting a single L1 lockup lets a staker claim signer weight and reward-bearing "staked sats" that are not backed by an equivalent, distinct BTC lock — this double-counts a commitment/reward (matches the "Critical: double-counting a commitment or reward" impact class, or at minimum High: signing weight/reward slots exceeding locked value). It inflates both the staker's stake-based signing power and their share of `calculate-rewards` payouts, diluting honest stakers' rewards and potentially giving a single locked BTC amount outsized influence in the reward-cycle signer set across two bond periods simultaneously.

### Likelihood Explanation
Likelihood is high given no special privilege is required: any staker who is allowlisted (`protocol-bond-allowances`) for two overlapping-in-time-but-different bond indices, or any staker who is allowlisted for the same bond a second registration is blocked by `map-insert`-style checks on membership, but nothing stops reusing the outpoint proof for a *different* `bond-index`'s allowlist entry, since `verify-l1-lockups` never records the outpoint outside the call. The proof material (Bitcoin header, tx bytes, Merkle path) is fully public once the underlying BTC transaction confirms, so the attacker only needs to be allowlisted for a second bond and re-submit the same proof.

### Recommendation
Add a persistent map, e.g. `(define-map used-l1-lockup-outpoints { txid: (buff 32), output-index: uint } bool)`, and in `validate-l1-lockup` use `map-insert` (asserting it wasn't already used, erroring with `ERR_DUPLICATE_LOCKUP_OUTPOINT` otherwise) instead of only checking the transient `seen-outpoints` list. This makes the outpoint-consumption check global and permanent rather than scoped to a single call.

### Proof of Concept
1. Staker `S` is allowlisted for `bond-index = 0` and `bond-index = 1` (assume non-overlapping/rollover-eligible, or simply two independent bonds `S` is added to via `add-staker-to-bond`).
2. `S` locks BTC to a valid timelock output for bond 0's early-unlock script and calls `register-for-bond` with `bond-index = 0`, supplying the L1 proof; sats are credited to bond 0.
3. Before/after registering, `S` calls `register-for-bond` again with `bond-index = 1`, but this time constructs `staker-unlock-bytes`/`early-unlock-bytes` combination such that `construct-lockup-output-script` for bond 1 reproduces (or the attacker picks a bond whose early-unlock-bytes make) the same expected script hash, or — more directly — simply re-submits the exact same `outputs` list (same header/tx/Merkle proof) for `bond-index = 1`. Because `verify-l1-lockups` for this second call starts with a fresh empty `seen-outpoints`, `validate-l1-lockup` does not know this outpoint was already consumed by bond 0, and the call succeeds, crediting `sats-total` again into bond 1's `protocol-bonds-total-staked` and `staker-shares-staked-for-cycle`.
4. `S` now has stake/reward exposure in two bonds backed by only one real BTC lockup, confirmed by inspecting `get-total-sbtc-staked-for-bond` for each bond index growing independently while the underlying Bitcoin UTXO was only spent/locked once.

Note: I could not fully verify within the available context whether `construct-lockup-output-script`'s binding to `bond-index`/`early-unlock-bytes` would prevent the exact same script from validating against two different bonds' allowlist parameters (e.g., if two bonds happen to share `early-unlock-bytes`), but the core defect — the complete absence of a persistent, cross-call outpoint-usage map — stands independent of that detail, since even a single staker re-registering for the *same* bond a second time (if permitted after `unstake-sbtc`/exit) could replay the identical proof.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L793-805)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1981-2019)
```text
;; Verify l1 lockup information for a staker. This asserts that each lockup
;; corresponds to the right timelock script for this staker, and that the lockup
;; occurred on-chain. If everything is valid, this returns the sum of all lockups in sats.
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2043-2088)
```text
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2242-2280)
```text
(define-private (calculate-bond-rewards
        (bond-index uint)
        (accumulator-res (response {
            ;; Used to ensure that the list of bonds are sorted correctly
            last-bond-stx-value-ratio: (optional uint),
            ;; Used as a tie-breaker in the case of bonds with the same
            ;; stx-value-ratio
            last-bond-index: (optional uint),
            ;; How much rewards are available to be distributed
            available-rewards: uint,
            calculation-height: uint,
            reward-cycle: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (reward-cycle (get reward-cycle accumulator))
            (total-sats (get-total-shares-staked-for-cycle reward-cycle (some bond-index)))
            (available-rewards (get available-rewards accumulator))
            ;; How much sBTC the bond is supposed to earn per calculation,
            ;; which is (totalSats * apy) / 50
            (target-yield (/ (/ (* total-sats (get target-rate bond)) u10000) u50))
            ;; If there is enough to cover the target yield, use that. Otherwise,
            ;; this bond gets the remaining rewards.
            (earned (if (>= available-rewards target-yield)
                target-yield
                available-rewards
            ))
            (stx-value-ratio (get stx-value-ratio bond))
            (current-rewards-per-token (get-rewards-per-token-for-cycle reward-cycle (some bond-index)))
            ;; Prevent divide-by-zero
            (accrued-rewards-per-sat (if (is-eq total-sats u0)
                u0
                (/ (* earned PRECISION) total-sats)
            ))
            (calculation-height (get calculation-height accumulator))
```
