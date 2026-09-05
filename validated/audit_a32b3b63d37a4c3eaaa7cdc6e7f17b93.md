Based on my investigation, I found a concrete concern in `pox-5.clar`'s Bitcoin L1 lockup verification logic, though I was unable to fully verify whether call-sites add additional protection before my tool budget ran out. I present the finding with that caveat noted explicitly.

### Title
Missing cross-transaction replay protection for L1 Bitcoin lockup outpoints in `pox-5.clar` allows double-counting sBTC bond sats - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`verify-l1-lockups` / `validate-l1-lockup` in `pox-5.clar` only deduplicate Bitcoin outpoints (`{txid, output-index}`) *within a single call*, via a `seen-outpoints` accumulator that is freshly initialized to `(list)` on every invocation. There is no persistent, contract-wide map recording which L1 outpoints have already been credited to a bond/stake position.

### Finding Description
`verify-l1-lockups` folds over the caller-supplied list of Bitcoin lockup proofs and builds `seen-outpoints` starting from an empty list each call: [1](#0-0) 

`validate-l1-lockup` checks `is-none (index-of? seen-outpoints outpoint)` to reject duplicates, but that check is only effective against duplicates present in the *same* list argument of the *same* call: [2](#0-1) 

Because `seen-outpoints` is reset every call (line 2013: `seen-outpoints: (list)`), nothing in this function itself prevents a staker from presenting the identical Bitcoin transaction/output (the same on-chain BTC lockup) in a second, separate call — e.g., in a later `register-for-bond` transaction for a different bond, or a repeat call — to get credited again for sats that were already counted toward a previous bond/stake commitment. The Merkle proof, block-header, script, and amount checks all validate that the sats *were* locked on Bitcoin once, but nothing ties that specific outpoint to a "already consumed" state that persists across transactions. I was not able to fully inspect the `register-for-bond` call-site and its surrounding state (e.g., whether it stores a global `used-outpoints`-style map elsewhere in the file) before exhausting available tool calls; my searches for terms like `used-outpoints`, `outpoint-used`, `txid-used`, `l1-lockup-used`, `already-claimed`, `processed-lockups` all returned no matches in `pox-5.clar`, which is consistent with there being no such persistent structure, but I could not confirm this with 100% certainty by reading every remaining line of the contract.

### Impact Explanation
If no persistent anti-replay state exists, an attacker could reuse a single BTC lockup output across multiple `register-for-bond` calls (potentially for multiple bonds, or the same bond after an unstake/restake cycle) to be credited with the same locked sats more than once — i.e., double-counting a Bitcoin commitment that was never actually re-locked. This matches the "Critical: double-counting a commitment or reward" category in the rules, since bond eligibility, reward-slot weight, or sBTC-lockup-backed accounting could be inflated without any additional Bitcoin being locked.

### Likelihood Explanation
Likelihood is moderate to low-confidence given the incomplete verification: the vulnerable-looking pattern (per-call-only dedup list) is confirmed by direct code reading, but whether the contract composes an additional persistent-state guard around the caller of `verify-l1-lockups` (which I could not fully inspect) determines whether this is actually exploitable. This should be treated as a lead requiring confirmation, not a fully proven exploit.

### Recommendation
Add a persistent map (e.g., `used-l1-outpoints: {txid: (buff 32), output-index: uint} -> bool`) that is checked and updated (via `map-insert`, failing on duplicate) inside `validate-l1-lockup`, so that once an outpoint has been credited to any bond/stake position, it can never be credited again in a future transaction.

### Proof of Concept
Conceptual (not fully verified against the live call graph):
1. Staker locks BTC in a single transaction/output satisfying the pox-5 timelock script.
2. Staker calls `register-for-bond` (bond A), presenting the L1 lockup proof; `verify-l1-lockups` validates it and credits the sats to bond A.
3. Staker calls `register-for-bond` again (bond B, or after unstaking bond A) with the *same* Bitcoin transaction/output as proof.
4. Because `seen-outpoints` in `validate-l1-lockup` is reinitialized per call, the duplicate is not detected across calls 2 and 3, and (absent any other persistent guard) the same sats are credited twice.

**Uncertainty flag:** I could not confirm within the available tool-call budget whether `register-for-bond`'s surrounding logic (which I could not fully read) already prevents this by other means (e.g., checking that the staker's `signer-manager`/bond record hasn't already used this outpoint, or requiring the BTC funds to be spent/moved between bonds). This finding should be verified against the full `register-for-bond` implementation before treating it as confirmed.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2072-2091)
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
```
