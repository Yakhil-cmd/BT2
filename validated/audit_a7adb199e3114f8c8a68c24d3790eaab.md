### Title
Missing persistent outpoint tracking in pox-5.clar L1 lockup verification permits double-counting the same Bitcoin lockup across multiple staking registrations - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`validate-l1-lockup` in `pox-5.clar` only deduplicates lockup outpoints (`txid` + `output-index`) *within a single call* to `verify-l1-lockups`, via a `seen-outpoints` list that is initialized fresh (`(list)`) on every invocation and never persisted to contract storage. [1](#0-0) [2](#0-1)  This means the same Bitcoin transaction output proving an L1 lockup of sats can be submitted again in a later, separate call (e.g., another registration or bond) and be accepted as new, distinct collateral, crediting the staker (or a different staker/bond) with sats that were never actually locked a second time on Bitcoin.

### Finding Description
`verify-l1-lockups` folds over a list of claimed L1 lockup outputs via `validate-l1-lockup`, checking each output's script, amount, BTC block header, and Merkle proof, and accumulating a `sum` of sats. [3](#0-2)  Duplicate protection is implemented purely as an in-memory accumulator (`seen-outpoints`, capped at 10 entries) that starts empty on each call: `(seen-outpoints: (list))` [4](#0-3) , and is only checked/extended within that same fold via `index-of?`/`append` [2](#0-1) [5](#0-4) . Nowhere in this function (or in the visible portions of the file) is there a persistent map (e.g. `map-set`) recording which `(txid, output-index)` outpoints have already been consumed by a prior call. Consequently, an unprivileged staker (or any account controlling the private key that produced the L1 timelock UTXO) could reuse the identical Bitcoin proof — the same `tx`, `header`, `leaf-hashes`, and `output-index` — across multiple separate transactions calling into the staking/bond registration flow that invokes `verify-l1-lockups`, and have the sats counted as locked collateral each time.

This breaks the equality the system is meant to enforce: total sats credited to stakers/bonds on Stacks must equal sats actually locked on Bitcoin. Reusing one lockup proof to count credit twice (or more) causes sats credited by an L1 proof that were never locked that many times — a direct double-counting of a commitment.

### Impact Explanation
This falls under the Critical category: "double-counting a commitment or reward" derived from an L1 proof, since the same on-chain Bitcoin lockup can be presented multiple times to back multiple staking positions without a corresponding increase in real locked BTC. Depending on how the resulting `sum` in sats is used downstream (e.g., toward `total-shares-staked-for-cycle`, reward-per-token accounting, or bond backing), this could allow a staker to claim signer weight, reward shares, or bond capacity disproportionate to actual locked collateral.

### Likelihood Explanation
Exploitation requires only owning/controlling the L1 timelock UTXO (which the staker already legitimately possesses, since it's their own lockup) and calling the registration path more than once with the same proof data — no privileged role, admin key, or another user's key is required. This is a normal, unprivileged staker action.

### Recommendation
Persist consumed outpoints in a durable map (e.g., `(map-set used-l1-outpoints { txid: txid, output-index: output-index } true)`) and check for prior existence of an outpoint across *all* calls (not just within the current fold) before accepting a lockup as valid collateral, rejecting with `ERR_DUPLICATE_LOCKUP_OUTPOINT` if it was already consumed in any earlier call.

### Proof of Concept
1. Staker A creates a valid L1 Bitcoin lockup UTXO with a given `txid`/`output-index`, matching the expected timelock script via `construct-lockup-output-script`.
2. Staker A calls the pox-5 registration flow that triggers `verify-l1-lockups`, submitting this UTXO as proof; `validate-l1-lockup` passes all checks (script, amount, header, Merkle proof) and the sats are credited.
3. Staker A calls the registration flow again (or registers a second bond/cycle) submitting the exact same `tx`, `header`, `leaf-hashes`, and `output-index` as proof.
4. Because `seen-outpoints` starts fresh at `(list)` for this new call [4](#0-3)  and there is no map lookup against previously-processed outpoints, `validate-l1-lockup` again accepts the same output as fresh valid lockup proof, crediting sats a second time without any additional BTC being locked.

**Note on scope/verification:** I was only able to inspect the `verify-l1-lockups`/`validate-l1-lockup` fold logic and the surrounding sBTC/reward-accounting helpers shown above; I could not fully trace every public entry point that calls `verify-l1-lockups` (e.g. a `register-l1-lockup` / bond-creation public function) within the indexed portion of `pox-5.clar` to confirm there is no additional, out-of-view persistent outpoint check elsewhere in the contract. If such a check exists outside the reviewed excerpt, this finding would be invalidated. Given the code shown, no such persistence mechanism is present, and the double-counting path appears real.

### Citations

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2086-2088)
```text
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2109-2111)
```text
            sum: (+ (get sum accumulator) (get amount output)),
            seen-outpoints: (unwrap-panic (as-max-len? (append seen-outpoints outpoint) u10)),
        })
```
