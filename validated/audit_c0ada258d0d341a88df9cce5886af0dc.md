Based on my investigation, there is no persistent global map tracking used Bitcoin outpoints in `pox-5.clar` — the `seen-outpoints` deduplication in `validate-l1-lockup` only exists as an ephemeral accumulator inside a single `fold` call, scoped to one invocation of `register-for-bond`/`verify-l1-lockups`.

### Title
Reusable L1 BTC lockup proof allows double-counting sats across separate bond registrations - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond` accepts an L1 Bitcoin timelock proof (`verify-l1-lockups` / `validate-l1-lockup`) that credits `sats-total` toward a bond's minimum-STX requirement and reward-share allocation. The only replay protection is a `seen-outpoints` list built and checked *within a single call* via `fold` [1](#0-0) . No persistent, contract-wide map records which `(txid, output-index)` outpoints have already been consumed by a previous `register-for-bond` call.

### Finding Description
`validate-l1-lockup` verifies the Bitcoin header, merkle proof, output script, and output amount for each claimed lockup output, and rejects duplicates only within the same call's `seen-outpoints` accumulator [2](#0-1) . Nothing in the contract persists which outpoints were already used by a *prior, separate* transaction. `verify-l1-lockups` is invoked once per `register-for-bond` call and returns a fresh `sum` each time based purely on re-verifying the same on-chain proof [3](#0-2) .

The reward-share and STX-lock bookkeeping only tracks `protocol-bond-memberships` per staker (a single entry, keyed on `tx-sender`), and `roll-sbtc`/rollover logic only nets sBTC differences for the *token-custody* path, not the L1-lockup path [4](#0-3) . Since `new-sbtc` is forced to `u0` on the L1 path [5](#0-4) , `roll-sbtc` never touches actual token custody for L1 lockups — the entire "is this BTC still locked and not already claimed elsewhere" guarantee rests solely on the transient `seen-outpoints` check.

### Impact Explanation
This would break the equality "sats credited by an L1 proof were never locked (or already counted) on Bitcoin" if the same physical BTC output can be presented again in a later `register-for-bond` call (e.g., for a different, non-overlapping future bond index) to receive a *second* allocation of `amount-sats` and thus a second share of stacking rewards / signer-slot backing, without any new BTC ever being locked for that second bond. Given the non-overlap gating (`bond-overlaps-new-position?`) only prevents concurrent membership for the *same staker*, not reuse of the *same outpoint*, this is a double-counting-of-commitment class bug (Critical, per the rules), assuming the outpoint's `unlock-burn-height` from the original transaction still satisfies `>= minimum-unlock-height` for the new bond and the transaction/header data can still be re-supplied.

### Likelihood Explanation
I could not fully confirm exploitability within the tool budget available — it's plausible the outpoint's Bitcoin-side timelock script (`construct-lockup-output-script`, keyed by `unlock-burn-height`) or some other constraint elsewhere in the contract (e.g., `settle-rewards`/`add-staker-to-bond-cycles` bookkeeping, or a check I did not locate) effectively prevents reuse across separate registrations. I was not able to locate a persistent used-outpoint map or an explicit cross-call replay guard in the portions of `pox-5.clar` I reviewed, but the contract is large (BOND_LENGTH_CYCLES logic, `update-bond-registration`, `announce-l1-early-exit`, and more) and I did not exhaustively review every function that touches bond memberships. Given this uncertainty, I flag this as a finding to be verified rather than a fully proven exploit.

### Recommendation
Add a persistent `define-map` (e.g., `used-l1-outpoints: {txid, output-index} -> bool`) that is checked and set in `validate-l1-lockup`/`verify-l1-lockups` across *all* calls (not just within one fold), so a given Bitcoin lockup output can only ever back one active bond registration for its lifetime.

### Proof of Concept
Not independently reproduced — would require: (1) staker registers for bond N using L1 lockup output O with `unlock-burn-height` satisfying bond N's minimum; (2) after or during a later non-overlapping bond M's registration window, the same staker (or, if the script binds only to `staker`+`unlock-burn-height`+bytes, potentially a colluding staker with the same unlock bytes) submits the identical proof for output O again in `register-for-bond(M, ...)`; if `verify-l1-lockups` re-validates and credits `sats-total` again without checking prior consumption, bond M receives sats-backed reward shares/signer weight with no corresponding new BTC lock. [1](#0-0) [2](#0-1)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L672-676)
```text
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L683-687)
```text
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-792)
```text
        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
            amount-sats: sats-total,
        })
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2074-2111)
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
        (ok {
            staker: (get staker accumulator),
            minimum-unlock-height: (get minimum-unlock-height accumulator),
            staker-unlock-bytes: (get staker-unlock-bytes accumulator),
            early-unlock-bytes: (get early-unlock-bytes accumulator),
            sum: (+ (get sum accumulator) (get amount output)),
            seen-outpoints: (unwrap-panic (as-max-len? (append seen-outpoints outpoint) u10)),
        })
```
