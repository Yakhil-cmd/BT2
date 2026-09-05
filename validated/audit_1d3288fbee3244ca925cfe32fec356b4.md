### Title
L1 lockup outpoint deduplication is per-call only, allowing the same Bitcoin lockup UTXO to be re-submitted across multiple `register-for-bond` calls to double-count sats credit - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-l1-lockups`/`validate-l1-lockup` in `pox-5.clar` verify that a list of Bitcoin UTXOs are genuine, unspent-looking lockups paying into a staker's timelock script, and sum their `amount` in sats to produce the staker's credited lockup total. Duplicate detection (`ERR_DUPLICATE_LOCKUP_OUTPOINT`) is implemented only via a `seen-outpoints` accumulator that is freshly initialized to `(list)` on every call to `verify-l1-lockups` [1](#0-0) . There is no persistent, contract-level map recording which Bitcoin outpoints have already been credited to a staker across separate transactions.

### Finding Description
`validate-l1-lockup` folds over the list of supplied lockup outputs and checks each one's Merkle proof, script hash, unlock height, and amount, then appends its `outpoint` (txid + output-index) to `seen-outpoints` to reject *within-call* duplicates [2](#0-1) . This `seen-outpoints` list is local to a single `verify-l1-lockups` invocation — it is constructed fresh each time from `(list)` inside `verify-l1-lockups` [3](#0-2)  — and is never persisted to a Clarity map keyed by outpoint. Because the verification only re-proves that a UTXO exists in a specific historical Bitcoin block and pays into the correct script (it never checks that the UTXO is still unspent on L1, nor marks it "consumed" in pox-5 state), the same lockup output can be presented again in a later, separate call and will pass all the same checks, since `seen-outpoints` starts empty again.

I was unable to fully trace how the returned `sum` from `verify-l1-lockups` is subsequently used by the calling public function (e.g. `register-for-bond`), because the grep for `register-for-bond`'s public definition and its use of `verify-l1-lockups`'s result did not return matching lines before the session ended. This is a gap that would need to be confirmed against the exact call site to know whether the credited "sats" figure feeds directly into `total-sbtc-staked`, `total-shares-staked-for-cycle`, or a similar accounting map that determines reward-slot/signing weight.

### Impact Explanation
If the `sum` returned by `verify-l1-lockups` is used to credit stake weight, reward-slot eligibility, or shares in `total-shares-staked-for-cycle` / `staker-shares-staked-for-cycle` without any persistent per-outpoint "already credited" record, an attacker could submit the same Bitcoin lockup proof in multiple `register-for-bond` calls (e.g. across separate roll-overs, or by simply calling `register-for-bond` again with the identical `lockups` argument) and have the sats double-counted — a stacking action that credits value that was never actually locked more than once on Bitcoin. This maps directly to the "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment" category, which is rated Critical.

### Likelihood Explanation
Likelihood cannot be confirmed as reachable without the missing call-site context (how `sum` feeds account state on repeat calls, and whether `register-for-bond` itself gates re-use of a bond position via a check unrelated to outpoints, e.g. bond-index uniqueness). If such a check exists and prevents any staker from calling `register-for-bond` twice for the same bond/lockup set, this would not be exploitable; the analysis here could not verify that gate.

### Recommendation
Persist a contract-level map (e.g. `l1-lockup-outpoint-used: {txid, output-index} -> bool`) that is checked and set permanently the first time an outpoint is credited via `validate-l1-lockup`, independent of the per-call `seen-outpoints` accumulator, so the same Bitcoin UTXO cannot be credited across multiple separate `register-for-bond`/`stake` calls.

### Proof of Concept
Not fully constructible from available context — reaching this bug requires confirming (1) that `verify-l1-lockups`'s `sum` is applied additively to a persistent stake/shares map on each call, and (2) that no other check (e.g., bond-index or nonce-based) blocks re-submission of the same `lockups` payload in a second transaction. This could not be verified with the tool calls available in this session.

### Citations

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2066-2088)
```text
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
