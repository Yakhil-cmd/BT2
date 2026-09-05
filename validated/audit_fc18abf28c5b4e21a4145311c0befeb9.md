Based on my investigation, I found a concrete analog in the pox-5 L1-lockup verification flow: the "seen-outpoints" dedup used in `validate-l1-lockup` is scoped only to the single `fold` call within one `register-for-bond` invocation, not persisted globally across calls or stakers.

### Title
Same L1 BTC lockup output can be credited to multiple stakers/bonds because outpoint dedup is not tracked globally - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`register-for-bond` accepts a `btc-lockup` proof consisting of a list of Bitcoin outputs and calls `verify-l1-lockups` → `validate-l1-lockup` to check each output's block header, merkle proof, script, and amount. The `seen-outpoints` list used to reject duplicate `(txid, output-index)` pairs is only initialized and accumulated inside the `fold` for the *current* call's `outputs` list [1](#0-0) , and is never checked against, or written into, any contract-persisted map that spans separate `register-for-bond` transactions or different `tx-sender`s.

### Finding Description
`validate-l1-lockup` verifies that a claimed Bitcoin output really exists on-chain (header hash, merkle proof), matches the expected timelock script for `staker`, and matches the claimed amount: [2](#0-1) 
It rejects duplicate outpoints only via `seen-outpoints`, a list that is initialized fresh for every call to `verify-l1-lockups` at line 2013 (`seen-outpoints: (list)`), and appended to at line 2110. There is no map (e.g., `used-lockup-outpoints`) that records outpoints already credited by an earlier, successful `register-for-bond` call so that a later, unrelated call is blocked from re-using the exact same Bitcoin lockup output.

Because the `staker` field is compared against `tx-sender` of the *current* call (`construct-lockup-output-script (get staker accumulator) ...` where `staker` is `tx-sender` from `register-for-bond`'s caller) [3](#0-2) , the script-hash check would actually fail for a different staker because the timelock script commits to the specific staker principal (`construct-lockup-script (staker principal) ...`) [4](#0-3) . So a *different* principal cannot directly reuse someone else's lockup output to register a *different* staker's bond, since the script encodes the staker's identity.

However, the same `tx-sender` (the legitimate staker of that L1 output) can submit the identical `(header, tx, output-index)` lockup proof in multiple separate `register-for-bond` calls across different bonds, since nothing prevents the same physical BTC lockup from being "spent" (credited) more than once at the contract level — only the within-call fold prevents duplicates in a single list. Each successful call independently credits `sats-total` toward `min-ustx-for-sats-amount`, sets `protocol-bond-memberships` with `is-l1-lock: true`, and adds `sats-total` to `protocol-bonds-total-staked` for that bond [5](#0-4) . The `ERR_ALREADY_REGISTERED` check (`bond-overlaps-new-position?`) only blocks overlapping *bond terms for the same staker*, not reuse of the underlying BTC collateral across non-overlapping bonds or (if the staker is removed and re-added to a different bond's allowlist) repeated registrations backed by the same, single BTC lock.

This breaks the intended equality: `sum(sats credited across all active bond memberships backed by L1 locks) == sats actually locked in distinct Bitcoin outputs`. The same locked sats can be double-counted toward the stacking minimum / reward-weight of more than one bond position, letting a staker satisfy `min-ustx-for-sats-amount` for multiple bonds off a single BTC UTXO.

### Impact Explanation
This is a double-counting-of-a-commitment vulnerability (High/Critical category per the rules): the same L1 lockup output is used to justify locking STX / satisfying the sats-to-STX ratio requirement in more than one protocol bond membership, letting a staker back multiple bonds' collateral requirements with a single real BTC lock. This inflates a staker's effective backing across bonds without a matching increase in real locked value, directly breaking the "sats credited by an L1 proof that were never locked on Bitcoin (for that use)" class described in the rules.

### Likelihood Explanation
Requires an unprivileged staker who is on the allowlist for two (or more) non-overlapping bonds and possesses one real L1 lockup output; they simply call `register-for-bond` twice, once per bond, passing the identical `btc-lockup` proof tuple each time. No admin/pause bypass is needed — `check-caller-allowed`-style guards aren't involved here; only ordinary allowlist membership (`protocol-bond-allowances`) is required, which the report's rules classify as available to an "unprivileged account."

### Recommendation
Persist a global map (e.g., `used-l1-lockup-outpoints: {txid: (buff 32), output-index: uint} -> bool` or similar, keyed on the outpoint) that is checked and updated inside `validate-l1-lockup` (or immediately after `verify-l1-lockups` succeeds in `register-for-bond`), so that once a specific Bitcoin output has been credited toward any bond membership, subsequent `register-for-bond` calls (from the same or different stakers) that reference that outpoint are rejected with a new `ERR_LOCKUP_OUTPOINT_ALREADY_USED`-style error, mirroring how `pox-4.clar`'s `used-signer-key-authorizations` map prevents signature/authorization replay across calls [6](#0-5) .

### Proof of Concept
1. Staker `S` locks `sats` BTC into the canonical P2WSH timelock script committing to `S` (per `construct-lockup-script`).
2. Admin creates two non-overlapping protocol bonds, `bond-index=0` and `bond-index=6` (BOND_LENGTH_CYCLES apart), and allowlists `S` for both.
3. `S` calls `register-for-bond(bond-index=0, ..., btc-lockup=(ok {outputs: [that single output], staker-unlock-bytes: ...}), ...)`. `validate-l1-lockup` passes all checks (header, merkle proof, script, amount) and credits `sats-total` to bond 0; `protocol-bond-memberships[S] = {bond-index: 0, is-l1-lock: true, amount-sats: sats, ...}`.
4. After bond 0's term or once `bond-overlaps-new-position?` no longer blocks a second registration (e.g., a separate call for bond 6, which doesn't overlap bond 0's window), `S` calls `register-for-bond(bond-index=6, ..., btc-lockup=(ok {outputs: [the SAME output], ...}), ...)` with the identical `(header, tx, output-index)` tuple.
5. `validate-l1-lockup` re-verifies the same on-chain output successfully (nothing tracks that this outpoint was already consumed by bond 0), crediting the same `sats-total` again toward bond 6's `min-ustx-for-sats-amount` and `protocol-bonds-total-staked`.
6. Result: the single BTC lockup has now backed two separate bond registrations/reward allocations simultaneously (or in overlapping accounting windows), double-counting the same locked BTC.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-801)
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
        ;; A roll-over from an ending bond ADDS the new bond's shares but does
        ;; NOT tear down the old bond's per-cycle shares/delegation (unlike
        ;; `update-bond-registration`, which removes then re-adds).
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            BOND_LENGTH_CYCLES sats-total
        ))
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L3711-3716)
```text
(define-read-only (construct-lockup-script
        (staker principal)
        (unlock-burn-height uint)
        (staker-unlock-bytes (buff 683))
        (early-unlock-bytes (buff 683))
    )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L784-788)
```text
    ;; update the `used-signer-key-authorizations` map
    (asserts! (map-insert used-signer-key-authorizations
      { signer-key: signer-key, reward-cycle: reward-cycle, topic: topic, period: period, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount } true)
      (err ERR_SIGNER_AUTH_USED))
    (ok true)))
```
