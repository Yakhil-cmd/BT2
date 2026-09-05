I found a concrete analog: `verify-l1-lockups`/`validate-l1-lockup` in `pox-5.clar` de-duplicate Bitcoin outpoints only *within a single call* (the `seen-outpoints` accumulator is a fresh, local list built up by `fold` and discarded once the function returns). There is no persistent, contract-level map recording which `(txid, output-index)` outpoints have already been credited to a staker/bond across separate transactions.

### Title
Double-counting of L1 Bitcoin lockup outputs across separate `register`/rollover calls due to non-persistent outpoint de-duplication - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`validate-l1-lockup` rejects a duplicate `(txid, output-index)` only against the `seen-outpoints` list built during the current `fold` invocation of `verify-l1-lockups`. This list is never persisted to a Clarity map, so the same Bitcoin lockup output can be presented again in a subsequent call (e.g., another `roll-sbtc`/registration transaction that re-submits the same lockup proof, possibly together with new lockups) and be credited again toward `sum`/staked sats, breaking the equality that each L1-locked satoshi should back exactly one unit of on-chain stacking credit.

### Finding Description
`verify-l1-lockups` initializes `seen-outpoints: (list)` fresh on every call [1](#0-0) , and `validate-l1-lockup` only checks `(is-none (index-of? seen-outpoints outpoint))` against that same transient accumulator [2](#0-1) , appending to it locally per call [3](#0-2) . Once the enclosing public function returns, this state is discarded — no `map-set` records the outpoint as consumed. Consequently, a staker (or anyone who can call the registration path with a staker's proof) can call the lockup-verification path in a follow-up transaction using the exact same Bitcoin transaction/output-index/merkle-proof, and it will again pass all checks (script hash match, amount match, merkle proof, height), because "already used" is never checked against persistent state.

This is the structural analog to the Caviar bug: in Caviar, ownership/derivation checks were only enforced within a local scope (the pool's own state), allowing the same underlying asset (the factory NFT) to be reused/re-entered across pools; here the same underlying asset (a specific satoshi-denominated UTXO already counted as locked) can be reused across calls because the "already consumed" check is scoped to a single function invocation rather than to global contract state.

### Impact Explanation
If a single Bitcoin L1 lockup output can be recognized as valid collateral more than once, `roll-sbtc`/staking accounting (`total-sbtc-staked`, `staker-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, `total-shares-staked-for-cycle`) can be incremented for sats that were never additionally locked on Bitcoin — this is a double-counting of a commitment, matching the Critical impact category ("sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment"). Depending on how the credited amount feeds into `roll-sbtc`'s sBTC pull/refund logic and reward-share accounting, this could let a staker claim disproportionate reward shares or manufacture staking weight unbacked by actual locked Bitcoin.

### Likelihood Explanation
Exploitability depends entirely on whether the *caller* of `verify-l1-lockups` (not shown/verified in the excerpt I could inspect) itself persists consumed outpoints in a separate map before/after invoking this helper. I was not able to locate such a persistent outpoint map (`map-set`/`map-get?` keyed on `{txid, output-index}`) anywhere in `pox-5.clar` via search, which is why this is flagged; however, I could not fully trace every call site of `verify-l1-lockups` (e.g., the top-level `register`/`bond`/`deposit` public function that invokes it) within my remaining search budget, so I cannot rule out that outpoint persistence exists elsewhere in the contract and is enforced by the caller.

### Recommendation
Persist consumed outpoints in a contract-level map (e.g., `(define-map used-l1-outpoints { txid: (buff 32), output-index: uint } bool)`), and in `validate-l1-lockup` (or its caller) assert `(is-none (map-get? used-l1-outpoints outpoint))` before crediting `sum`, then `map-set` it to `true` as part of the same transaction — so that de-duplication survives across calls, not just within one `fold`.

### Proof of Concept
1. Staker submits a valid L1 lockup proof (`tx`, `header`, `leaf-hashes`, etc.) for a Bitcoin UTXO of `amount` sats via the registration path that calls `verify-l1-lockups`; `sum` is credited and `roll-sbtc`/share-staking maps are updated accordingly.
2. In a later transaction (e.g., a rollover or another registration call), the staker resubmits the identical `tx`/`output-index`/merkle-proof for the same UTXO (which is still unspent/valid on L1, since spending it isn't required by the check — only that its script/amount match).
3. Because `seen-outpoints` is reinitialized to `(list)` for this new call, the duplicate check in `validate-l1-lockup` never fires, and the same sats are credited to `sum` a second time, inflating the staker's on-chain locked/staked accounting without any additional Bitcoin being locked.

**Note on confidence:** I could not fully verify the top-level public function(s) that call `verify-l1-lockups` (register/bond/rollover entry points) within the remaining tool budget to confirm whether they add their own persistent outpoint tracking; this finding should be validated against the full call graph in `pox-5.clar` before treating it as confirmed rather than a code-level red flag.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2004-2016)
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2104-2112)
```text
        (ok {
            staker: (get staker accumulator),
            minimum-unlock-height: (get minimum-unlock-height accumulator),
            staker-unlock-bytes: (get staker-unlock-bytes accumulator),
            early-unlock-bytes: (get early-unlock-bytes accumulator),
            sum: (+ (get sum accumulator) (get amount output)),
            seen-outpoints: (unwrap-panic (as-max-len? (append seen-outpoints outpoint) u10)),
        })
    )
```
