Confirmed: there is no persistent, global map recording consumed Bitcoin outpoints in `pox-5.clar`. The `seen-outpoints` list built in `verify-l1-lockups` / `validate-l1-lockup` is a transient accumulator that only exists for the duration of a single `fold` over the `outputs` list supplied in one `register-for-bond` call [1](#0-0) . It is reset to `(list)` on every invocation of `verify-l1-lockups` [2](#0-1) , and `validate-l1-lockup` only checks the current call's list, the Bitcoin header/merkle proof, the script hash, and the amount — it never checks any contract-level map keyed by `(txid, output-index)` to see if that same Bitcoin output was already credited by a prior transaction [3](#0-2) .

### Title
Missing global outpoint tracking in `verify-l1-lockups` allows the same Bitcoin lockup UTXO to be re-submitted across separate `register-for-bond` calls, double-counting locked sats - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond` credits `sats-total` sBTC-equivalent stake to a bond by verifying, via `verify-l1-lockups`/`validate-l1-lockup`, that a Bitcoin transaction output pays into the canonical timelock P2WSH for the staker [4](#0-3) . Duplicate-outpoint protection is implemented only as an in-memory list scoped to the current `fold` call (`seen-outpoints`), which is fixed per the changelog entry "Prevent counting duplicate lockups in pox-5 `register-for-bond`" [5](#0-4) . There is no contract-level map that durably records which `(txid, output-index)` pairs have already been consumed by a *previous, separate* transaction.

### Finding Description
`validate-l1-lockup` verifies: the script hash matches the expected staker lockup script, the amount, the Bitcoin block header, and the merkle inclusion proof, then adds the output's amount to a running `sum`, tracking already-seen outpoints in `seen-outpoints` purely to prevent duplicates *within the list passed in this single call* [6](#0-5) . Nothing in this function or its caller (`verify-l1-lockups`, `register-for-bond`) checks a persistent map to see if this outpoint was already redeemed by an earlier `register-for-bond` transaction. Because `register-for-bond` can be called again after a staker's earlier bond membership is cleared (e.g., after `unstake-sbtc`, after a bond period rolls over and `protocol-bond-memberships` is deleted, or simply once `ERR_ALREADY_REGISTERED` no longer blocks a new bond period), a staker can present the *same* Bitcoin lockup transaction/output proof again in a subsequent call and have `sats-total` credited a second time. This inflates `protocol-bond-memberships` (`amount-sats`) and `protocol-bonds-total-staked` for a second (or Nth) bond period without any new Bitcoin funds being locked [7](#0-6) , breaking the equality that on-chain reward-eligible sats must equal sats actually locked on Bitcoin.

### Impact Explanation
This breaks the core invariant that sBTC/sats credited toward a bond must correspond 1:1 with STX/BTC actually locked. Re-using the same Bitcoin UTXO proof to register for a new bond period after the old membership is cleared results in double-counting a commitment that was only ever locked once on Bitcoin, inflating a staker's/signer's effective stake and reward-slot weight beyond what is actually collateralized (a Critical-class outcome per the stated impact categories: "double-counting a commitment or reward").

### Likelihood Explanation
Requires only an unprivileged staker who already went through the L1 bond lockup flow once and later exits or rolls that membership (both are standard, permissionless flows: `unstake-sbtc`/bond expiry/rollover). No admin, signer, or miner privileges are needed to re-submit the same lockup proof to a subsequent `register-for-bond` call.

### Recommendation
Add a persistent contract map (e.g., `used-l1-outpoints: {txid: (buff 32), output-index: uint} -> bool`) that is checked and set inside `validate-l1-lockup`/`verify-l1-lockups`, rejecting any outpoint that has ever been credited in a prior transaction, not just within the current call's list.

### Proof of Concept
I could not fully verify a concrete end-to-end reproduction (e.g., confirming exactly which state-clearing paths — `unstake-sbtc`, bond rollover, or a fresh bond-period allowlist re-add — leave the same outpoint eligible to be resubmitted) without executing the contract test suite (`stacks-node/src/tests/pox_5_integrations.rs`) or the property tests in `contrib/core-contract-tests`, which is outside what I can run in this read-only analysis. The existing integration test `check_pox_5_register_for_bond_l1_lockup_lifecycle` only asserts that *within a single call* duplicate outpoints are rejected and that a *second* `register-for-bond` from the same staker while still a bond member fails with `ERR_ALREADY_REGISTERED` [8](#0-7)  — it does not test resubmission of the same lockup proof after that membership is cleared (i.e., after unstake or bond rollover), which is the scenario this finding depends on. I recommend a Devin session with full test-execution access to confirm whether `unstake-sbtc`/rollover fully clears the state needed to make this exploitable.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-676)
```text
    (let (
            (signer (contract-of signer-manager))
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
```

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2057-2112)
```text
    (let (
            (accumulator (try! accumulator-res))
            (block (try! (parse-block-header (get header lockup))))
            (unlock-burn-height (get unlock-burn-height lockup))
            (expected-script-hash (try! (construct-lockup-output-script (get staker accumulator)
                unlock-burn-height (get staker-unlock-bytes accumulator)
                (get early-unlock-bytes accumulator)
            )))
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
    )
```

**File:** CHANGELOG.md (L89-89)
```markdown
* Prevent counting duplicate lockups in pox-5 `register-for-bond`.
```

**File:** stacks-node/src/tests/pox_5_integrations.rs (L1417-1429)
```rust
/// - submitting the same lockup outpoint three times in the L1 proof list
///   is rejected with `ERR_DUPLICATE_LOCKUP_OUTPOINT` (u46) — the per-output
///   dedup inside `validate-l1-lockup` trips before the post-fold sum check,
///   and the failure leaves the staker with no bond membership and no STX lock
/// - the honest single-output proof still registers (guards against
///   too-aggressive dedup)
/// - STX is locked, with unlock height set to the bond's unlock-burn-height
/// - the bond membership records `is-l1-lock: true` (the membership reads
///   `(is-ok btc-lockup)`)
/// - the staker's sBTC balance is unchanged (no sBTC `ft-transfer?` runs
///   on the L1 path)
/// - a second `register-for-bond` from the same staker fails with
///   `ERR_ALREADY_REGISTERED` (u9) and does not perturb the existing lock
```
