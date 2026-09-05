### Title
Bitcoin lockup outpoints are only deduplicated within a single call, allowing the same L1 lockup UTXO to be replayed across separate `register-for-bond` calls to double-count locked sats - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`verify-l1-lockups` / `validate-l1-lockup` in `pox-5.clar` only prevent duplicate outpoints *within the same call*, via a `seen-outpoints` accumulator that is freshly initialized to `(list)` on every invocation. There is no contract-level persistent registry of outpoints that have already been credited to a staker/bond in a prior call. This mirrors the analog bug class of the external report: the contract's internally recorded state (credited sats) can drift from — and in this case exceed — the real, one-time economic event on the base chain (a single BTC lockup output), because the bookkeeping mechanism (a transient, per-call list) cannot enforce a global invariant across calls.

### Finding Description
`validate-l1-lockup` builds up `sum` of sats credited from a set of Bitcoin lockup outputs supplied in a single `lockups` argument, guarding against duplicates only via the fold's local `seen-outpoints` accumulator: [1](#0-0) [2](#0-1) 

`verify-l1-lockups` calls this fold with a brand-new `seen-outpoints: (list)` on every top-level call: [3](#0-2) 

The checks performed on each output are: the timelock script hash matches the staker/bond, the unlock height is valid, the BTC block header is valid, and a merkle proof anchors the transaction in that block: [4](#0-3) 

None of these checks reference any persisted, contract-wide record of txids/outpoints that were already credited in a previous call to `register-for-bond` (or any other entry point that consumes `verify-l1-lockups`). As long as the same UTXO still satisfies the timelock-script and merkle-proof checks (which it will, since the Bitcoin transaction itself never changes), a staker can present the exact same lockup output again in a subsequent call and have its `amount` summed into `sum` again, crediting additional `amount-sats` to a new bond/stake position without any additional BTC being locked.

This is the same equality violation as the wibBTC/Curve case: the contract's internal ledger (`total-sbtc-staked`, per-staker/per-signer `shares-staked` maps fed by `roll-sbtc`) is supposed to track 1:1 the real collateral, but the dedup mechanism that is supposed to enforce "one lockup = one credit" only operates in-memory for a single transaction and is discarded afterward.

### Impact Explanation
If exploitable, an attacker can register multiple bonds (or a bond and a stake) backed by the same single L1 BTC lockup, causing `amount-sats`/shares to be double (or N-times) counted in `total-sbtc-staked`, `signer-shares-staked-for-cycle`, and `staker-shares-staked-for-cycle` without locking additional Bitcoin. This directly breaks the "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment" invariant called out in scope, and would let a staker claim reward shares and sBTC rewards disproportionate to actual locked BTC — a Critical-severity theft/unbacked-credit issue.

### Likelihood Explanation
Requires only an unprivileged staker controlling one BTC lockup UTXO and calling the public `register-for-bond` entry point more than once with lockup proof data that includes the same outpoint; no privileged key, miner, or other user's key is needed. The main constraint would be any node-side or contract-side gating on unlock-height overlaps for the *same* bond index re-registration (`pox_rollover_v5` gates roll-overs of the *same* staker's *existing* lock), but nothing in `validate-l1-lockup`/`verify-l1-lockups` itself prevents reusing the outpoint for a **different** bond index or in combination with a different signer, since the persisted dedup state does not exist at all.

### Recommendation
Introduce a contract-persisted map (e.g., `(define-map used-l1-outpoints {txid: (buff 32), output-index: uint} bool)`) that is checked and set inside `validate-l1-lockup` (or immediately after `verify-l1-lockups` succeeds and before/while updating `total-sbtc-staked`), so that once an outpoint has been credited to any staker/bond, any future presentation of the same outpoint is rejected with a dedicated error (e.g., `ERR_DUPLICATE_LOCKUP_OUTPOINT` applied globally, not just per-call).

### Proof of Concept
1. Staker Alice locks `X` sats on Bitcoin in a single UTXO whose timelock script commits to her principal, an `unlock-burn-height`, and `staker-unlock-bytes`/`early-unlock-bytes` for bond `B1`.
2. Alice calls `register-for-bond` for bond `B1`, submitting the Bitcoin transaction/merkle-proof for that UTXO. `verify-l1-lockups` validates it and credits `X` sats via `roll-sbtc`, incrementing `total-sbtc-staked` and her bond shares by `X`.
3. Alice calls `register-for-bond` again for a different bond `B2` (or for the same bond after it rolls over, in a way not blocked by the roll-over gating), submitting the *same* Bitcoin transaction/output/merkle-proof.
4. Because `seen-outpoints` is reinitialized to `(list)` for this new call, and there is no persistent record that this outpoint was already used, `validate-l1-lockup` again returns `sum = X` and passes all checks (script, unlock height, header, merkle proof all still validate against the same real Bitcoin transaction).
5. `roll-sbtc` credits another `X` sats worth of stake/shares to Alice for `B2`, so the contract now records `2X` sats staked backed by only `X` real locked sats — `total-sbtc-staked` and the staker/signer share maps have double-counted a single L1 commitment.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2074-2103)
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
```
