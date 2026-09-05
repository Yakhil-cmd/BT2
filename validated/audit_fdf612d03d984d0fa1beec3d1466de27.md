### Title
Reused L1 Bitcoin lockup outpoints can back multiple bond registrations, causing sats to be credited without new BTC ever being locked - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond` in `pox-5.clar` allows a staker to prove BTC collateral via `verify-l1-lockups`/`validate-l1-lockup`, which sum the `amount` of each Bitcoin output supplied. Duplicate detection (`seen-outpoints`) is only maintained *within a single call's fold* and is never persisted to contract storage, so nothing prevents the exact same `(txid, output-index)` outpoint from being submitted again in a later `register-for-bond` call (e.g., after a rollover, or after a bond membership ends) to be credited as fresh collateral for a new bond period.

### Finding Description
`verify-l1-lockups` (stackslib/src/chainstate/stacks/boot/pox-5.clar:1984-2019) folds `validate-l1-lockup` over the caller-supplied list of BTC outputs, starting each call with an empty `seen-outpoints: (list)` accumulator [1](#0-0) . Inside the fold, `validate-l1-lockup` checks the outpoint against `seen-outpoints` only to reject duplicates *inside this one call* [2](#0-1) , then adds the outpoint's amount to `sum` and appends it to the local list [3](#0-2) .

There is no map (e.g., `used-l1-outpoints`) anywhere in the contract that records outpoints already credited across separate transactions/calls — a `grep` for "outpoint" over `pox-5.clar` outside of this local fold state found nothing. This means the same real BTC lockup transaction/output can be presented again in a subsequent `register-for-bond` call by the same staker (e.g., on a rollover into bond N+1, N+2, ... as permitted by `bond-overlaps-new-position?`/`verify-bond-rollover-window`) and be counted again as `sats-total` backing a brand-new bond membership, while the underlying Bitcoin UTXO is still the same single locked amount. `sats-total` directly determines the staker's credited `amount-sats` and minimum required `amount-ustx` (via `min-ustx-for-sats-amount`) recorded in `protocol-bond-memberships` and totalled into `protocol-bonds-total-staked` [4](#0-3) , both of which feed signer-set weight and reward computations.

Because the `staker-unlock-bytes` embed the staker's principal into `construct-lockup-output-script`, a *different* principal cannot claim someone else's lockup output, but the *same* staker is not prevented from re-presenting an already-used, still-locked BTC output as "new" collateral for a subsequent bond term. This breaks the equality that `protocol-bonds-total-staked`/`amount-sats` should represent real, once-counted Bitcoin collateral — one BTC lockup output could be double-counted across bond periods without new sats ever being locked for the second credit.

I was not able to fully confirm within this scan whether other checks elsewhere (e.g., in `bond-overlaps-new-position?`, `verify-bond-rollover-window`, or node-side burnchain-op validation) implicitly prevent this reuse from producing net-additional signer weight/reward beyond what the original lockup already justified; the contract functions I inspected did not contain any such outpoint-level idempotency check, and `pox-locking/src/**` was not found to intersect with this L1-lockup verification path.

### Impact Explanation
If unmitigated, this allows sats credited by an L1 proof that were never (newly) locked on Bitcoin to be double-counted toward signer-set weight/reward eligibility across successive bond periods — matching the "double-counting a commitment or reward" / "unbacked... reward" class of Critical/High impact in scope. This directly affects `protocol-bonds-total-staked` and per-staker `amount-sats`, which underlie signer voting power and reward share calculations in pox-5.

### Likelihood Explanation
The exploit requires only an unprivileged staker replaying a BTC transaction they already control/broadcast — no admin, miner, or other-user key needed. It leverages the normal, sanctioned "rollover" flow (`bond-overlaps-new-position?` explicitly permits non-overlapping consecutive bond registrations), so the attacker does not need to bypass any access control, only to resupply identical proof data. Whether this yields net gain depends on downstream reward/weight formulas not otherwise re-verifying real, distinct collateral, which I could not fully trace within the tool budget available.

### Recommendation
Persist a global (or per-bond) map of claimed L1 outpoints (e.g., `used-l1-lockup-outpoints: {txid, output-index} -> bool`) and assert non-membership before crediting `sats-total` in `validate-l1-lockup`, marking it used on success — mirroring the fix pattern from the referenced report (make the "already counted" check explicit and persistent rather than relying on transient, call-scoped state).

### Proof of Concept
1. Staker Alice locks BTC in a P2WSH timelock output `(txid T, vout V)` scripted to her principal via `construct-lockup-output-script`.
2. Alice calls `register-for-bond` for bond index `N`, submitting `(T, V)` as her only lockup output; `validate-l1-lockup` accepts it and credits `amount-sats = sats(T,V)` [3](#0-2) .
3. Once bond `N`'s rollover window opens (`verify-bond-rollover-window`), Alice calls `register-for-bond` again for bond `N+6` (non-overlapping, so `bond-overlaps-new-position?` allows it), submitting the *same* `(T, V)` outpoint again.
4. `verify-l1-lockups` starts with a fresh empty `seen-outpoints` for this new call, so the duplicate check does not trigger, and `sats-total` is credited again for bond `N+6` using the identical, previously-counted BTC lockup [5](#0-4) .
5. No BTC was newly locked between steps 2 and 4, yet `protocol-bond-memberships`/`protocol-bonds-total-staked` record a fresh `amount-sats` credit for bond `N+6`.

### Citations

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2031-2056)
```text
(define-private (validate-l1-lockup
        (lockup {
            height: uint,
            tx: (buff 100000),
            output-index: uint,
            header: (buff 80),
            leaf-hashes: (list 14 (buff 32)),
            tx-count: uint,
            tx-index: uint,
            amount: uint,
            unlock-burn-height: uint,
        })
        (accumulator-res (response {
            staker: principal,
            minimum-unlock-height: uint,
            staker-unlock-bytes: (buff 683),
            early-unlock-bytes: (buff 683),
            sum: uint,
            seen-outpoints: (list 10 {
                txid: (buff 32),
                output-index: uint,
            }),
        }
            uint
        ))
    )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2086-2088)
```text
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
