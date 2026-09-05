### Title
Missing cross-transaction replay protection for L1 Bitcoin lockup outpoints allows double-counting of the same BTC-locked sats across multiple bond registrations - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`pox-5.clar`'s L1-lockup verification path (`verify-l1-lockups` / `validate-l1-lockup`) only prevents *within a single call* re-use of the same Bitcoin `(txid, output-index)` outpoint. There is no persisted, cross-call ledger of already-credited outpoints, so the same on-chain BTC lockup transaction can be submitted as proof in more than one `register-for-bond`/bond-registration call, crediting the same physically-locked sats as backing for multiple reward-share positions.

### Finding Description
`verify-l1-lockups` seeds the fold accumulator with a fresh, empty `seen-outpoints` list on every invocation: [1](#0-0) 

`validate-l1-lockup`'s own doc comment states the dedup is scoped only "in this call": [2](#0-1) 

The actual duplicate check only looks at the in-memory `seen-outpoints` accumulator built during the current fold, not any contract-persisted map keyed by `(txid, output-index)`: [3](#0-2) 

Because this accumulator is discarded when the transaction finishes (nothing is written to a `define-map` recording spent outpoints), the same Bitcoin transaction output that was already accepted as proof of a lockup in one `register-for-bond` (or bond roll-over/registration) call can be re-submitted as the lockup proof in a subsequent, unrelated registration call — for the same bond index at a later date, for a different bond index, or even by presenting it again after `unstake-sbtc`-style flows — and it will pass `verify-block-header`/`verify-merkle-proof`/script checks again since those checks only prove the Bitcoin transaction exists and matches the expected timelock script, not that it hasn't already been used to back a stake.

This breaks the intended equality: `total sats credited across staker bond positions == sats actually locked on Bitcoin by the staker`. A single locked UTXO could back two (or more) concurrent reward-earning positions, i.e. sats are credited that were never separately locked — matching the explicitly in-scope bug class "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment."

### Impact Explanation
If the same L1 lockup proof can be accepted more than once, the protocol will compute reward shares (`staker-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, `total-shares-staked-for-cycle`) based on more aggregate "locked" sats than physically exist, letting an attacker double their share of sBTC rewards relative to their real Bitcoin collateral, or letting reward slots/signing weight exceed the actual value backing them. This is a Critical-severity double-counting of a commitment as defined by the impact taxonomy.

### Likelihood Explanation
Exploitability depends on whether `register-for-bond` (not shown in the retrieved excerpt) has additional persisted state that independently binds a given outpoint or lockup tx to a single bond/staker for its lifetime; this could not be fully confirmed from the code sections I was able to retrieve, since the full body of `register-for-bond`/`update-bond-registration` was not shown in the tool output. However, the module's own inline documentation explicitly scopes duplicate-outpoint protection to "this call," and no `define-map` tracking consumed outpoints was found in the reviewed portions of `pox-5.clar`, which strongly suggests cross-call replay is possible for any staker who can call the registration entry points during the appropriate window (bond setup/rollover). Because this requires no privileged role, only an unprivileged staker replaying their own previously-accepted lockup proof, it satisfies the "unprivileged-account analog" constraint.

### Recommendation
Persist accepted outpoints in a durable map (e.g. `(define-map used-l1-outpoints { txid: (buff 32), output-index: uint } bool)`), and in `validate-l1-lockup` assert `(map-insert used-l1-outpoints outpoint true)` (failing with a new `ERR_DUPLICATE_LOCKUP_OUTPOINT` if already present) instead of/in addition to the transient `seen-outpoints` list, so a given Bitcoin lockup output can only ever back one stake position for its lifetime.

### Proof of Concept
Conceptual PoC (full harness not verifiable from the retrieved code, since `register-for-bond`'s complete body was not available in this session):
1. Staker locks `N` sats in a single Bitcoin UTXO under the pox-5 timelock script for `bond-index = 0`.
2. Staker calls `register-for-bond` (or equivalent) with a valid Merkle proof for that UTXO; `verify-l1-lockups` accepts it and credits `N` sats of stake for bond 0.
3. Staker calls the registration entry point again (e.g., after bond 0 fully unlocks per `verify-bond-rollover-window`, or for a distinct `bond-index`) submitting the *same* Bitcoin transaction/output as proof.
4. Because `seen-outpoints` is re-initialized to `(list)` on each call and no persisted map records the outpoint as already consumed, `validate-l1-lockup` accepts it a second time, crediting `N` sats of stake again without any additional BTC ever being locked.

*Note: I was unable to retrieve the full definition of `register-for-bond` in this session to conclusively rule out an additional external safeguard (e.g., allowlist single-use flags) that might mitigate this at a higher level; this should be verified against the complete function body before remediation.*

### Citations

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2065-2088)
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
```
