### Title
Double-crediting of the same Bitcoin lockup UTXO across separate `pox-5.clar` staking calls due to non-persistent outpoint tracking - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
The reported JOJO bug is a missing-validation pattern: a value that should have been checked against an attacker-controlled input (`minReceive`) was silently skipped in one code path while sibling functions enforced it. The `pox-5.clar` L1-lockup verification (`verify-l1-lockups` / `validate-l1-lockup`) shows the same class of defect: the de-duplication check that is supposed to stop a single Bitcoin UTXO from being credited more than once is scoped only to the current call, not persisted on-chain, so the same already-verified UTXO can be re-submitted in a later call to credit `amount-sats` again.

### Finding Description
`verify-l1-lockups` (stackslib/src/chainstate/stacks/boot/pox-5.clar, lines 1984-2019) folds over the caller-supplied list of Bitcoin outputs via `validate-l1-lockup`, seeding the accumulator with an **empty** `seen-outpoints: (list)` on every invocation: [1](#0-0) 

`validate-l1-lockup` then checks the outpoint (`txid`, `output-index`) against `seen-outpoints` and rejects duplicates only *within that same fold* (`ERR_DUPLICATE_LOCKUP_OUTPOINT`), then appends it to the accumulator's local list: [2](#0-1) 

There is no persistent, contract-level map (e.g. `used-l1-lockups { txid, output-index } -> bool`) that records outpoints already credited in a *prior* call. My search for such a map (`used-lockup`, `lockup-outpoint`, or similar) found nothing outside this local `seen-outpoints` accumulator (which is re-initialized every call). Consequently, a staker who has legitimately locked BTC in a single UTXO and has already been credited `amount-sats` for it in one call to the entry point that invokes `verify-l1-lockups` (registration/stake path referenced by `contrib/core-contract-tests/tests/pox-5/commands/RegisterForBondErrInvalidBtcHeader.ts`) can submit the *same* Merkle proof/UTXO again in a subsequent call. Because the header, Merkle proof, and script checks (`verify-block-header`, `verify-merkle-proof`, `is-eq (get script output) expected-script-hash`) will all pass again (they are stateless proofs of an already-mined, still-valid transaction), the function returns the same `amount-sats` sum a second time, letting the caller be credited stake/shares for BTC that was only locked once.

This mirrors the JOJO defect exactly: a validation that exists (duplicate-outpoint rejection) is scoped too narrowly and thus fails to enforce the invariant across the full attack surface, breaking the equality "credited sats == sats actually and currently locked on Bitcoin."

### Impact Explanation
If exploitable, this breaks the equality between locked BTC and credited staking shares: the staker's `amount-sats`/shares used for reward distribution (`total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, `staker-shares-staked-for-cycle`) would be inflated relative to the true amount of BTC locked, double-counting a single commitment. That directly matches the Critical category ("double-counting a commitment or reward") since it can dilute or misallocate sBTC/reward-per-token payouts to stakers who did not lock corresponding BTC, at the expense of legitimate stakers/the reward pool.

### Likelihood Explanation
Likelihood depends entirely on whether the public entry point that calls `verify-l1-lockups` (the registration/staking function) can be invoked more than once for the same staker/bond with an already-used lockup output, and whether any *other* state check outside `verify-l1-lockups` (not visible in the excerpts I retrieved) prevents resubmission. I was not able to fully trace every caller of `verify-l1-lockups` or all state transitions in the ~4000-line `pox-5.clar` file within the available tool budget, so I cannot confirm with certainty that no other guard (e.g., a bond-level "already registered" flag) blocks the second call. This is a material gap in my verification.

### Recommendation
Persist a global map keyed by `(txid, output-index)` (or `(bond-index, txid, output-index)`) recording every outpoint that has already been credited via `verify-l1-lockups`/`validate-l1-lockup`, and reject any lockup whose outpoint is already present in that map — analogous to how `used-signer-key-authorizations` prevents replay of signer-key authorizations in `pox-4.clar`. The `seen-outpoints` list should supplement, not replace, this persistent check.

### Proof of Concept
Not fully constructible from the retrieved code alone — I could not confirm the exact public entry point signature and full call sequence for L1-lockup registration/staking within the available search budget. A concrete PoC would require: (1) identifying the public function invoking `verify-l1-lockups`, (2) confirming it can be called more than once by the same staker referencing the same Bitcoin transaction/output, and (3) demonstrating the resulting shares/`amount-sats` are credited twice. This should be validated by a follow-up review of the full `pox-5.clar` staking/registration flow before treating this as fully confirmed.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2072-2110)
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
```
