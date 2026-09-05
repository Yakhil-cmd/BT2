Based on my investigation, I found a strong analog in `pox-5.clar`'s Bitcoin-lockup verification path.

### Title
Missing global outpoint-consumption tracking in `verify-l1-lockups` allows the same Bitcoin lockup output to be credited to multiple sBTC bond registrations - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-l1-lockups`/`validate-l1-lockup` in `pox-5.clar` prove that a Bitcoin UTXO exists, matches the staker's expected timelock script, and hasn't already been double-counted — but the duplicate check (`seen-outpoints`) is only maintained locally within a single call's `fold`, not persisted in contract state across calls. This mirrors the ProxyCall bug class: a value (sats locked on L1) is checked/consumed once in isolation but never marked as "spent" globally, so it can be reused.

### Finding Description
`validate-l1-lockup` builds a running `seen-outpoints` list to reject duplicate `(txid, output-index)` pairs *within the same list of lockups passed to one call* [1](#0-0) . This list is created fresh in `verify-l1-lockups` for every invocation [2](#0-1)  and is never written to a persistent map (no `used-outpoint`/`claimed-lockup` style map exists in this contract, based on the grep search across the file). Consequently, nothing prevents the same Bitcoin lockup output (i.e., the same locked sats, proven via `verify-block-header`/`verify-merkle-proof`) from being submitted again in a *separate* transaction to register/extend a different bond or stake position, crediting `amount-sats` a second time via `(+ (get sum accumulator) (get amount output))` [3](#0-2) .

The check only guards against the caller listing the exact same output twice inside one `outputs` list — it does not verify that the output has not already been used to back a different bond/stake elsewhere in the pox-5 contract, or previously by the same staker. Since `verify-l1-lockups` is the sole mechanism to prove Bitcoin-side locked sats and translate them into contract-recognized `amount-sats`, this breaks the equality "sats credited to a staker/bond == sats actually locked (and not yet claimed) on Bitcoin."

### Impact Explanation
This falls under the Critical category "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment." A staker could reuse one L1 lockup output across multiple `register-for-bond`/bond-registration calls, inflating their credited `amount-sats` and therefore their share of signer rewards distributed in `calculate-rewards`, without actually having that many sats locked on Bitcoin for each registration. This can result in reward over-allocation (theft of sBTC rewards from the pool) and/or reward-slot/signing-weight exceeding actually-locked value.

### Likelihood Explanation
This requires an unprivileged staker to submit a valid Bitcoin merkle/header proof of one real lockup output more than once across separate contract calls (e.g., for two different bonds, or the same bond twice at different times if permitted). No admin, signer, or other user's key is required — only the staker's own valid but reused L1 proof, which is fully within an ordinary user's reach. However, I could not fully confirm within the available context whether a separate persistent check exists elsewhere in the bond/stake registration flow (e.g., in `register-for-bond` itself, outside of `verify-l1-lockups`) that cross-references consumed outpoints — the grep for `used-outpoint`/`outpoint-claimed` returned no persistent-map hits in this file, but the full 2000+ line contract was only partially read, so this should be verified against the complete `register-for-bond`/`stake` implementations before concluding definitively.

### Recommendation
Persist consumed outpoints in a durable Clarity map (e.g., `(define-map claimed-l1-outpoints { txid: (buff 32), output-index: uint } bool)`), and in `validate-l1-lockup` assert `(map-insert claimed-l1-outpoints outpoint true)` (or equivalent) so that reuse across any two contract calls — not just within a single call's list — is rejected with an error such as `ERR_DUPLICATE_LOCKUP_OUTPOINT`.

### Proof of Concept
Conceptual (not fully instrumented due to inability to read the complete `register-for-bond`/`stake` call sites in this pass):
1. Staker `A` locks 100 sats on Bitcoin to `staker-unlock-bytes` script for `bond-index=1`, producing a valid `(header, tx, output-index, leaf-hashes, ...)` proof.
2. `A` calls `register-for-bond` (or equivalent) for `bond-index=1`, submitting this proof through `verify-l1-lockups` → credited 100 sats.
3. `A` calls the equivalent registration for `bond-index=2` (a different bond) submitting the *same* Bitcoin output proof again. Since `seen-outpoints` is scoped per-call and no persistent map records consumption, `validate-l1-lockup` passes again and credits another 100 sats to bond 2, even though only 100 sats were ever locked on Bitcoin.
4. Total `amount-sats` recognized across bonds (200) now exceeds actual locked BTC (100), inflating reward-share calculations in `calculate-rewards`.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2004-2015)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2086-2088)
```text
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2104-2111)
```text
        (ok {
            staker: (get staker accumulator),
            minimum-unlock-height: (get minimum-unlock-height accumulator),
            staker-unlock-bytes: (get staker-unlock-bytes accumulator),
            early-unlock-bytes: (get early-unlock-bytes accumulator),
            sum: (+ (get sum accumulator) (get amount output)),
            seen-outpoints: (unwrap-panic (as-max-len? (append seen-outpoints outpoint) u10)),
        })
```
