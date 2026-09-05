### Title
Missing persistent outpoint tracking in `verify-l1-lockups` allows double-crediting of the same Bitcoin lockup UTXO across multiple `register-for-bond` calls - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-l1-lockups` / `validate-l1-lockup` in `pox-5.clar` only guards against duplicate outpoints *within a single call* via a locally-built `seen-outpoints` list that starts empty every time the fold runs. There is no contract-level map that persists which Bitcoin outpoints have already been consumed by a prior successful lockup-credit, so the same L1 lockup UTXO can be resubmitted in a separate transaction and be credited again.

### Finding Description
`verify-l1-lockups` seeds the fold accumulator with an empty `seen-outpoints: (list)` on every invocation [1](#0-0) , and `validate-l1-lockup` only rejects a duplicate outpoint against that same in-call list via `(asserts! (is-none (index-of? seen-outpoints outpoint)) ERR_DUPLICATE_LOCKUP_OUTPOINT)` [2](#0-1) . This is structurally identical to the reported bug class: a state-mutating operation is missing a *persistent* "already consumed/already enabled" guard, and instead only checks a transient/local condition, so a caller can repeat the operation and have the same underlying collateral (there, ETH already collected; here, sats already proven-locked on L1) credited a second time. No `define-map` recording previously-used `(txid, output-index)` outpoints across calls was found in `pox-5.clar`; the check exists only inside the single `fold` call's accumulator, which is discarded once the transaction completes.

Since the sum returned by `verify-l1-lockups` (line 2017) feeds into crediting staker/signer sats for a reward cycle (e.g., via the staking/bond-registration flow that updates `staker-shares-staked-for-cycle` / `signer-shares-staked-for-cycle`), an attacker who has one valid, provable Bitcoin lockup output can submit it in `register-for-bond` (or equivalent staking entry point) once, then submit the exact same Bitcoin transaction/output proof again in a second, independent call. Because the per-call `seen-outpoints` list resets, the second call's `validate-l1-lockup` has no record of the outpoint having been used previously and will accept it again, crediting the sats a second time.

### Impact Explanation
This breaks the equality between "sats actually locked once on Bitcoin" and "sats credited inside pox-5," letting an attacker double-count a single L1 lockup commitment to inflate their staked/bonded sats (and thus signing weight or reward share) without locking additional Bitcoin. This matches the Critical impact category: "double-counting a commitment or reward."

### Likelihood Explanation
High — the attacker only needs a single legitimately-locked Bitcoin UTXO and the standard Merkle/header proof data they already possess from creating the first lockup; no other user's key, admin, or special network condition is required. They simply call the registration/staking entry point a second time with the identical proof.

### Recommendation
Add a persistent map (e.g., `used-l1-lockup-outpoints`) keyed by `{ txid, output-index }` that is checked and updated (via `map-insert`, asserting it wasn't already present) the first time an outpoint is successfully validated in `validate-l1-lockup`/`verify-l1-lockups`, so that once an outpoint has been credited it can never be credited again in any future transaction, not just within the same call.

### Proof of Concept
1. Attacker locks BTC to the timelock script derived from `construct-lockup-output-script` for their staker principal, producing outpoint `O = {txid, output-index}` with a valid Merkle/header proof.
2. Attacker calls the pox-5 registration entry point (which internally calls `verify-l1-lockups`) with `O`, receiving sats credited to their staked/bonded shares for a reward cycle.
3. Attacker calls the same registration entry point again with the identical proof for `O`. Because `seen-outpoints` is reinitialized to `(list)` at the start of `verify-l1-lockups` for this new call [1](#0-0) , `validate-l1-lockup`'s duplicate check passes trivially, and the same sats amount is credited a second time [3](#0-2) .

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2080-2111)
```text
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
```
