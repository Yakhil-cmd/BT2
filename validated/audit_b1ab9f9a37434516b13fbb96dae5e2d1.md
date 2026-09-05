### Title
`register-for-bond`'s per-call L1 lockup dedup is not a global replay guard, allowing the same on-chain BTC lockup to be re-proved into a second bond and double-count sats collateral - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond` accepts a Bitcoin "L1 lockup" proof (header + merkle proof + output script match) as evidence that a staker locked BTC, and credits `sats-total` (via `verify-l1-lockups` / `validate-l1-lockup`) toward bond collateral without ever recording that a specific `(txid, output-index)` outpoint has already been credited to a bond. The only anti-duplication check, `seen-outpoints`, is scoped to the single call's fold and is discarded afterward.

### Finding Description
`validate-l1-lockup` builds a `seen-outpoints` accumulator that is initialized fresh on every call to `verify-l1-lockups` and rejects only duplicates *within the same list of outputs* passed to the same transaction: [1](#0-0) [2](#0-1) 

There is no persistent map (e.g., `used-l1-outpoints`) checked/inserted across calls — a `grep` for `used-outpoints`/`used-l1-lockups`/`claimed-l1-lockups` across the repo found no such construct guarding `register-for-bond`, in contrast to the explicit `used-signer-key-authorizations` map that guards signer-key auth reuse in `pox-4.clar`/`pox-5.clar`: [3](#0-2) 

`register-for-bond` accepts a fresh (or rolled-over) bond membership, and credits `amount-sats` from `verify-l1-lockups`/`sats-total` into `protocol-bond-memberships`, `protocol-bonds-total-staked`, and per-cycle share maps, exactly once per call — but the underlying Bitcoin evidence (the still-existing, unspent P2WSH output committed only to `staker` + `unlock-burn-height`) remains re-provable in any subsequent, unrelated `register-for-bond` call by the same staker once their prior bond/registration state has been cleared (e.g. after a bond ends, or after `announce-l1-early-exit`, which zeroes `amount-sats` in the membership but does not spend or mark the Bitcoin UTXO): [4](#0-3) [5](#0-4) [6](#0-5) 

Because `construct-lockup-output-script` deterministically derives the same P2WSH from `(staker, unlock-burn-height, staker-unlock-bytes, early-unlock-bytes)`, and `unlock-burn-height`/`early-unlock-bytes` are drawn from the *targeted bond's* parameters rather than from a value bound uniquely to a single registration attempt, the same Bitcoin transaction output can satisfy `validate-l1-lockup`'s script/amount checks again for a *different* `bond-index` with the same `unlock-burn-height` requirement (or after `announce-l1-early-exit` zeroes out the sats credited from the same BTC), as long as `bond-overlaps-new-position?` no longer treats the staker as actively holding an overlapping membership. This breaks the equality "sats credited to a bond == sats actually, currently locked on Bitcoin for that staker" — the same BTC collateral (or the record of that collateral) can be counted toward more sats-collateral commitments than physically exist, a double-counting of a commitment.

This is the direct structural analog of the reported `TransferWhitelist.whitelistAddress` bug: an entry (there, an address in a whitelist array; here, a Bitcoin lockup outpoint used as sats-collateral evidence) can be submitted/consumed more than once because the checking is local to a single call rather than tracked persistently against reuse.

### Impact Explanation
If a staker can re-credit the same physical BTC lockup as `sats-total` for two overlapping/sequential bond registrations, `protocol-bonds-total-staked` and per-cycle bond share maps (`total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, `staker-shares-staked-for-cycle`) would double-count collateral that is not actually backed 1:1 by locked sats, inflating reward-eligible weight and reward payouts drawn from `sbtc-token` reserves relative to real backing. This corresponds to "double-counting a commitment or reward" (Critical) under the rules.

### Likelihood Explanation
Exploitability depends on whether the on-chain lifecycle (`announce-l1-early-exit`, bond term boundaries, `bond-overlaps-new-position?`) can actually be driven into a state where the same still-valid/still-unspent P2WSH output can be re-submitted to `register-for-bond` for a second bond period before the underlying BTC is spent by the staker on Bitcoin. I was not able to fully verify from the available context whether `verify-bond-rollover-window`, bond overlap checks, or the requirement that `unlock-burn-height` matches each specific target bond's `get-bond-l1-unlock-height` sufficiently forecloses this path in all cases — the integration tests I found (`stacks-node/src/tests/pox_5_integrations.rs`) only exercise the *same-call* dedup (`ERR_DUPLICATE_LOCKUP_OUTPOINT`) and the immediate re-registration rejection (`ERR_ALREADY_REGISTERED`), not a cross-bond-period replay of the identical lockup transaction after a legitimate lifecycle transition (unstake/early-exit/rollover to a later, non-overlapping bond).

### Recommendation
Add a persistent map (e.g., `used-l1-lockup-outpoints: {txid, output-index} -> bool`) that is checked and inserted (via `map-insert`, mirroring `used-signer-key-authorizations`) inside `validate-l1-lockup`, so that once an outpoint has been credited toward any bond membership, it can never be credited again regardless of the calling bond-index or staker lifecycle state.

### Proof of Concept
Not conclusively constructible from the available codebase context: exploitation requires confirming a concrete state transition (e.g., `register-for-bond` → `announce-l1-early-exit` → later `register-for-bond` for a non-overlapping bond period, or a rollover after natural bond expiry) in which the exact same `(header, tx, output-index)` L1 lockup tuple used before is accepted a second time by `verify-l1-lockups`/`validate-l1-lockup` and produces a second non-zero `amount-sats` credit in `protocol-bond-memberships`/`protocol-bonds-total-staked`, without the staker having produced a new Bitcoin lockup transaction. This would need to be verified with a Devin session running the `contrib/core-contract-tests` or `stacks-node/src/tests/pox_5_integrations.rs` harness (e.g. `check_pox_5_register_for_bond_l1_lockup_lifecycle`) to attempt exactly this two-registration sequence with the identical lockup tuple across two different `bond-index` values or across an early-exit/rollover boundary.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L784-805)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1230-1246)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2072-2088)
```text
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

**File:** contrib/boot-contracts-unit-tests/boot_contracts/pox-4.clar (L248-262)
```text
;; State for tracking used signer key authorizations. This prevents re-use
;; of the same signature or pre-set authorization for multiple transactions.
;; Refer to the `signer-key-authorizations` map for the documentation on these fields
(define-map used-signer-key-authorizations
    {
        signer-key: (buff 33),
        reward-cycle: uint,
        period: uint,
        topic: (string-ascii 14),
        pox-addr: { version: (buff 1), hashbytes: (buff 32) },
        auth-id: uint,
        max-amount: uint,
    }
    bool ;; Whether the field has been used or not
)
```
