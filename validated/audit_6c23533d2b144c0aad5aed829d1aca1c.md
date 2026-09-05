### Title
Reused L1 Bitcoin lockup UTXO double-counted across sequential bonds — sats credited that were never re-locked on Bitcoin (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond` accepts an L1 Bitcoin lockup proof and converts it into a `sats-total` figure via `verify-l1-lockups`/`validate-l1-lockup`. The duplicate-outpoint guard (`seen-outpoints`) is only a fresh, function-local accumulator that exists for the lifetime of a single call — there is no contract-persisted set of previously-consumed Bitcoin outpoints. A staker can therefore present the exact same BTC UTXO proof to more than one `register-for-bond` call (for sequential, non-overlapping bonds) and have the identical locked sats credited into `protocol-bonds-total-staked` and per-cycle share bookkeeping for each bond, even though only one real BTC output was ever locked.

### Finding Description
`validate-l1-lockup`'s dedup check only guards against the same outpoint appearing twice **inside the `outputs` list of one call**: [1](#0-0) [2](#0-1) 

`seen-outpoints` is initialized to `(list)` fresh on every invocation of `verify-l1-lockups`, and is never written to any persistent map, so the contract has no memory of which Bitcoin outpoints were already used to back a previous `register-for-bond` call.

The only binding that ties a lockup output to a specific principal is the P2WSH script hash, which commits to `staker` and to a `unlock-burn-height` chosen by the staker at lock time (not the bond's specific unlock height, only `>= minimum-unlock-height` for that bond): [3](#0-2) [4](#0-3) 

Because a single chosen `unlock-burn-height` can satisfy the `minimum-unlock-height` requirement of several different (sequential) `bond-index` values, the same staker can call `register-for-bond` multiple times — once per bond — reusing the identical `outputs` proof each time. `verify-l1-lockups` will happily re-validate it and return the same `sats-total` again, since nothing rejects "this outpoint was already credited to bond 0."

`register-for-bond`'s roll-over path explicitly does **not** remove the old bond's per-cycle stake/shares when a staker moves to a new bond: [5](#0-4) 

So each successive registration accumulates the same `sats-total` into `protocol-bonds-total-staked` for a *new* bond index, on top of the value already recorded for the *old* bond index. The end state is that one Bitcoin-locked UTXO backs the recorded stake/collateral of multiple bonds simultaneously.

### Impact Explanation
`protocol-bonds-total-staked` and the per-cycle stake/shares populated via `add-staker-to-bond-cycles`/`add-staker-to-signer-cycles` are the basis for reward distribution and signing weight in pox-5. Double- (or N-times-) counting a single BTC lockup inflates a staker's (and their signer's) recorded stake across multiple bonds without any additional Bitcoin ever being locked. This directly matches the in-scope failure mode "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment," which is rated Critical (double-counting a commitment or reward) under the rules, since it lets recorded collateral/stake exceed what is actually locked on Bitcoin, and inflates reward/signing weight beyond the real locked value.

### Likelihood Explanation
Exploitation requires no privileged role — it only needs an allowlisted staker (an ordinary unprivileged account) to submit the same lockup proof to `register-for-bond` for a second, non-overlapping bond after their first bond's term. The `ERR_ALREADY_REGISTERED` check only blocks *overlapping* bond memberships for the same staker, not reuse of the same underlying UTXO, so this path is reachable through normal contract usage without any additional signature or admin action.

### Recommendation
Persist consumed L1 outpoints in a durable map (e.g., `(define-map used-l1-outpoints {txid: (buff 32), output-index: uint} bool)`) and check/insert into it inside `validate-l1-lockup`, so that once an outpoint has been credited to any bond it can never be credited again, regardless of which `register-for-bond` call or bond-index it is presented for.

### Proof of Concept
1. Staker A is allowlisted for bond 0 and bond 1 (sequential, non-overlapping cycles), each requiring an L1 lockup with `minimum-unlock-height` no later than some height `H`.
2. Staker A locks BTC to a P2WSH output built with `construct-lockup-output-script(A, H', staker-unlock-bytes, early-unlock-bytes)` where `H' >= H` (satisfying both bonds' minimum unlock height).
3. Staker A calls `register-for-bond(bond-index=0, ..., btc-lockup=(ok {outputs: [thatUTXO], ...}))`. `verify-l1-lockups` validates it and returns `sats-total = amount`. `protocol-bonds-total-staked[0]` is set to `amount`.
4. After bond 0's term progresses into its rollover window, staker A calls `register-for-bond(bond-index=1, ..., btc-lockup=(ok {outputs: [the SAME UTXO], ...}))`. `validate-l1-lockup`'s `seen-outpoints` check is a fresh, per-call list and does not see the prior use, so verification succeeds again with the same `sats-total = amount`.
5. `protocol-bonds-total-staked[1]` becomes `amount` as well, and per the roll-over comment, bond 0's per-cycle shares were never torn down — so the same real Bitcoin lockup now backs recorded stake in both bond 0 and bond 1 concurrently, with only one BTC output ever locked.

Note: I could not trace how `protocol-bonds-total-staked` and per-cycle shares are ultimately consumed for reward payout in the reward-distribution code within the available context, so the precise numeric payout impact (e.g., magnitude of reward inflation) is not independently confirmed here — this would benefit from a full Devin session with complete file access to trace `settle-rewards`/`settle-staker-rewards` consumption of these values.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L793-801)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2004-2018)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2074-2085)
```text
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2086-2088)
```text
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L3694-3730)
```text
;; The staker is bound to the script via a hashed commitment rather than a
;; cleartext push: the OP_ELSE branch requires revealing the 32-byte
;; `sha256(to-consensus-buff? staker)` preimage of the committed hash
;; `<H> = sha256(sha256(to-consensus-buff? staker))`.
;;
;; The constructed script has this structure:
;; ```
;; OP_IF
;;     <unlock-burn-height> OP_CHECKLOCKTIMEVERIFY
;; OP_ELSE
;;     OP_SIZE <32> OP_EQUALVERIFY
;;     OP_SHA256 <H> OP_EQUALVERIFY
;;     <early-unlock-bytes>
;; OP_ENDIF
;; OP_VERIFY
;; <staker-unlock-bytes>
;; ```
(define-read-only (construct-lockup-script
        (staker principal)
        (unlock-burn-height uint)
        (staker-unlock-bytes (buff 683))
        (early-unlock-bytes (buff 683))
    )
    ;; @format-ignore
    (ok
        (concat
            0x63           ;; OP_IF
            (try! (push-c-script-num unlock-burn-height))
            0xb167         ;; OP_CHECKLOCKTIMEVERIFY, OP_ELSE
            0x82012088a820 ;; OP_SIZE, <32>, OP_EQUALVERIFY, OP_SHA256, OP_PUSHBYTES_32
            (sha256 (sha256 (unwrap-panic (to-consensus-buff? staker))))
            0x88           ;; OP_EQUALVERIFY
            early-unlock-bytes
            0x6869         ;; OP_ENDIF, OP_VERIFY
            staker-unlock-bytes
        )
    )
```
