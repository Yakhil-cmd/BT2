### Title
L1 BTC lockup outpoints are only deduplicated within a single `register-for-bond` call, allowing the same Bitcoin UTXO to be reused across multiple bonds to double-count sats — ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`register-for-bond`'s L1 path verifies a Bitcoin lockup via `verify-l1-lockups` / `validate-l1-lockup`, which checks a Merkle proof and block header against the claimed UTXO and rejects duplicate `(txid, output-index)` pairs — but only *within the fold of a single call* via a freshly-initialized `seen-outpoints: (list)` accumulator. [1](#0-0) [2](#0-1) 
No persistent, contract-wide map records BTC outpoints that have already been credited across separate transactions/bonds; `validate-l1-lockup`'s duplicate check only consults the in-memory `seen-outpoints` list built up during that one call's fold. [3](#0-2) 

### Finding Description
The bug-class analog to the LayerZero report is a missing "ordering/uniqueness" enforcement between two systems that are supposed to stay in equilibrium: the amount of BTC actually locked on Bitcoin (L1) and the amount of sats PoX-5 credits toward a staker's bond (L2 ledger). In the LayerZero case, the missing ordered-execution option let the L2 ledger update while the L1 vault rejected the corresponding message, breaking the invariant that L2 balance changes are backed by L1 state. Here, the equivalent invariant is: *sats credited to `protocol-bond-memberships`/`protocol-bonds-total-staked` must correspond 1:1 to real, once-only-spent BTC lockup outputs*.

`register-for-bond` computes `sats-total` by calling `verify-l1-lockups`, which folds over the caller-supplied list of BTC outputs and asserts, per call, that no `(txid, output-index)` repeats within that same list [4](#0-3) . However, this `seen-outpoints` state is local to the `fold` and is discarded after the call returns; it is never persisted to a Clarity map (e.g., a `used-l1-outpoints` map keyed by `{txid, output-index}`). Consequently, nothing in the contract prevents:
- The same staker calling `register-for-bond` a second time (for a different `bond-index`, since bonds don't overlap in `bond-overlaps-new-position?`) using an *identical* Merkle proof for the same already-spent-or-still-locked BTC output.
- Two different stakers (in principle, anyone able to construct a valid witness matching `construct-lockup-output-script`) each separately calling `register-for-bond` with proof of the same UTXO, since the script check binds the output script to the caller's `tx-sender` and bond parameters, but the underlying Merkle-proof/Bitcoin-header verification only proves the UTXO exists on L1 — it does not prove exclusivity of use across PoX-5 state.

Since `verify-l1-lockups`'s result directly sets `sats-total`, which is then written into `protocol-bond-memberships` (`amount-sats`) and `protocol-bonds-total-staked` [5](#0-4) , each additional `register-for-bond` call replaying the same BTC lockup proof credits the same physical satoshis a second (or Nth) time into a different bond's share/reward accounting — without any additional BTC being locked. This breaks the "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment" equality explicitly listed as in-scope impact classes.

### Impact Explanation
Double-crediting the same L1 lockup sats inflates a staker's (or colluding stakers') share of `protocol-bonds-total-staked` and their proportional signing weight / reward entitlement in `settle-rewards` / `settle-staker-rewards`, without a corresponding increase in real backing BTC. This is a case of unbacked accounting: reward slots/signing weight now exceed the value actually locked, and honest participants' rewards are diluted, since total-staked accounting no longer matches real locked collateral. Per the rules, this maps to a High-severity class: "signing weight or reward slots exceeding locked value."

### Likelihood Explanation
The action requires no privileged role — any allowlisted staker for two bonds (or a staker able to satisfy the allowlist and signer-manager checks for a second bond) can trigger this simply by submitting `register-for-bond` twice with the same BTC-lockup proof payload, which is fully attacker-controlled calldata. No admin, miner, or other-user key is needed, and the exploit does not rely on the attacker forfeiting only their own stake (it inflates against the shared reward/signing-weight pool). The main precondition is having (or being allowlisted for) two non-overlapping bond slots, which is a normal, permissionless part of the protocol's registration flow.

### Recommendation
Persist consumed L1 outpoints in a durable contract map (e.g., `(define-map used-l1-lockup-outpoints { txid: (buff 32), output-index: uint } bool)`), and in `validate-l1-lockup`, check/insert against this global map (via `map-insert`, rejecting on failure) in addition to the per-call `seen-outpoints` list, so the same Bitcoin UTXO can never be credited toward more than one `register-for-bond` (or other sats-crediting) call across the contract's lifetime.

### Proof of Concept
1. Staker Alice is allowlisted for `bond-index = 0` and `bond-index = 6` (non-overlapping periods).
2. Alice locks BTC in a single UTXO matching the `construct-lockup-output-script` for bond 0, and obtains one valid Merkle-proof/header package proving that lockup.
3. Alice calls `register-for-bond(bond-index=0, ..., btc-lockup=ok({outputs: [that UTXO], ...}), ...)`. `verify-l1-lockups` succeeds and credits `sats-total` sats to bond 0 [6](#0-5) .
4. Alice calls `register-for-bond(bond-index=6, ..., btc-lockup=ok({outputs: [the SAME UTXO], ...}), ...)` with the identical Merkle proof. `bond-overlaps-new-position?` permits this because bond 6 starts after bond 0 ends, and `verify-l1-lockups`'s `seen-outpoints` check is reset for this new call, so the duplicate outpoint is not detected. `sats-total` is credited again to bond 6's `protocol-bonds-total-staked` and Alice's new membership [5](#0-4) .
5. Alice now holds credited sats-based shares in two bonds backed by only one real BTC lockup, inflating her signing weight/reward entitlement across the protocol without additional locked collateral.

(Note: full exploitability depends on whether `bond-overlaps-new-position?`, `verify-bond-rollover-window`, and the allowlist/signer-manager checks can be simultaneously satisfied for two bonds by the same staker or coordinated stakers reusing the same proof; this was inferred from the code shown and not confirmed via a running test — flagging this as the main uncertainty. I could not find a persisted outpoint-tracking map anywhere in the pox-5.clar contract via search, which supports the core finding that dedup is call-scoped only.)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-795)
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2021-2031)
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
(define-private (validate-l1-lockup
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
