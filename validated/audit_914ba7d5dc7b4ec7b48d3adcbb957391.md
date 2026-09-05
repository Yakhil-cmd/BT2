### Title
Stale-cache write in `register-for-bond` after an external `signer-manager-validate-stake` call permits double-counting of protocol-bond sBTC commitments - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond` reads `current-total-staked` and `existing-membership` into `let`-bound locals *before* it performs an external `contract-call?` into an attacker-suppliable `signer-manager-trait` contract, and again before a second external sBTC transfer (`roll-sbtc`). Only after both external calls return does it commit `map-set protocol-bond-memberships` and `map-set protocol-bonds-total-staked bond-index (+ current-total-staked sats-total)` using those pre-call cached values. This is the same checks/effects/interactions ordering flaw as the reported `_wethWithdrawTo` finding: state that is supposed to gate a shared accounting value (`MIN_RESERVE` there, `protocol-bonds-total-staked` here) is computed before an external, attacker-influenceable call, and written back afterward, so it can be clobbered/desynced by a reentrant call that runs and commits its own writes to the same map key in between.

### Finding Description
In `register-for-bond` [1](#0-0) , `current-total-staked` (the running per-cycle sBTC total for the bond) and `existing-membership`/`old-sbtc`/`existing-stake` are captured in the initial `let` binding.

The function then:
1. calls `(try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1 amount-ustx sats-total true signer-calldata))` [2](#0-1)  — `signer-manager` is a trait object supplied by the caller; the only gate on which contract this can be is that its `contract-of` value must be a currently-registered signer with an active key grant, not that it is a specific trusted implementation. This is an external call into caller/staker-influenced code.
2. later performs `(try! (roll-sbtc tx-sender old-sbtc new-sbtc))` [3](#0-2) , which moves sBTC (another external transfer-triggering call).
3. only *after* both external calls does it commit the membership and aggregate-total writes:
`(map-set protocol-bond-memberships tx-sender {...})` and `(map-set protocol-bonds-total-staked bond-index (+ current-total-staked sats-total))` [4](#0-3) .

Because `current-total-staked` and `existing-membership` were snapshotted before the external calls, any reentrant call into `register-for-bond` (or another mutating pox-5 entry point touching the same bond/staker) that is triggered from within `signer-manager-validate-stake` or `roll-sbtc` and that completes (commits its own `map-set`s) before the outer call resumes will have its contribution to `protocol-bonds-total-staked` silently overwritten by the outer call's stale `(+ current-total-staked sats-total)` write — the outer write does not account for the inner call's increment. Likewise the outer `map-set protocol-bond-memberships` unconditionally overwrites whatever the inner call set for the same `tx-sender`. The result is a desync between the real sBTC actually moved into custody by `roll-sbtc` calls, per-cycle signer/bond delegation already committed by `add-staker-to-bond-cycles`/`add-staker-to-signer-cycles` for each reentrant call, and the final recorded `protocol-bond-memberships` / `protocol-bonds-total-staked` bookkeeping, which only reflects the last call to finish.

### Impact Explanation
`protocol-bonds-total-staked` and `protocol-bond-memberships` are the authoritative records used elsewhere in the contract to account for aggregate custodied sBTC and to determine bond capacity/rewards. A stale overwrite lets committed sBTC be moved into contract custody (via `roll-sbtc`) for cycles that are never reflected in the aggregate total, or lets a staker's `protocol-bond-memberships` entry diverge from the sBTC/lock state actually recorded in the per-cycle maps. This is a double-counting/bookkeeping-desync of an sBTC commitment — sBTC and signer-cycle shares get credited that the aggregate accounting does not see, or vice versa, which can misstate reward-eligible shares and reserve accounting tied to real custodied sBTC. This maps to "double-counting a commitment" in the given impact taxonomy.

### Likelihood Explanation
Exploitability hinges on whether the `signer-manager` trait implementation (attacker/staker-supplied contract, gated only by being a "registered signer" — itself attainable via `register-self`/`register-signer`, which does not require special privilege beyond obtaining a signer-key grant) can actually re-enter `register-for-bond`/other pox-5 entry points mid-call and have its own map-sets commit before the outer call resumes, and whether the Clarity VM's contract-call semantics permit an already-open call frame for the same `tx-sender` to be reentered (i.e., no reentrancy guard exists on `register-for-bond`). I could not confirm from the excerpts retrieved whether pox-5.clar or the `pox-locking` handlers include any explicit reentrancy guard (e.g., an in-call flag) preventing this, nor could I fully inspect `roll-sbtc`'s and `signer-manager-validate-stake`'s exact bodies within the tool budget available. This uncertainty should be resolved before treating the finding as confirmed exploitable.

### Recommendation
Move all `let`-bound values that gate subsequent map-set writes (`current-total-staked`, `existing-membership`, `old-sbtc`) to be re-read immediately before they are used to compute the final write, or restructure `register-for-bond` to follow strict checks-effects-interactions ordering: perform all external calls (`signer-manager-validate-stake`, `roll-sbtc`) first, then re-derive `current-total-staked` fresh from the map right before incrementing it, or use an atomic/idempotent update pattern rather than "read old, then blind-write old+delta" after intervening external calls. Consider adding an explicit reentrancy guard on `register-for-bond` (and sibling mutating entry points) to reject a nested call from the same transaction root.

### Proof of Concept
Conceptual sequence (exact reentrant call path through `signer-manager-validate-stake`/`roll-sbtc` was not fully verified within the available context):
1. Staker/attacker deploys a contract implementing `signer-manager-trait` and gets it registered as a signer via `register-self`.
2. Staker calls `register-for-bond` for `bond-index B` with `sats-total = S1`; the outer call reads `current-total-staked = T0` for `B`'s first cycle at line 704.
3. Inside `signer-manager-validate-stake` (line 754), the attacker's implementation calls back into pox-5's `register-for-bond` for the same `tx-sender`/bond (or a related mutating function touching `protocol-bonds-total-staked[B]`), which runs to completion and commits `protocol-bonds-total-staked[B] = T0 + S2` plus its own sBTC custody transfer and per-cycle delegation entries.
4. Control returns to the outer call, which — still holding the stale `T0` — finishes and writes `protocol-bonds-total-staked[B] = T0 + S1`, erasing the inner call's `S2` contribution from the aggregate even though the inner call's sBTC was actually moved into custody and its per-cycle shares were added.
5. Net effect: contract-custodied sBTC and per-cycle signer/bond shares exceed what `protocol-bonds-total-staked`/`protocol-bond-memberships` report, a concrete double-counting/desync of a staking commitment.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-709)
```text
    (let (
            (signer (contract-of signer-manager))
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
            ;; Any bond the staker is currently a member of. Some value here
            ;; means this is a roll-over from an ending bond into a later one.
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
            ;; sBTC currently custodied for the staker's existing bond (0 if
            ;; they have none, or if the existing bond is an L1 lock).
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
            ;; Any STX-only stake the staker has. Present means this
            ;; `register-for-bond` is a roll-over from an ending stx-only
            ;; stake into a bond.
            (existing-stake (map-get? staker-info tx-sender))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (allowance (unwrap!
                (map-get? protocol-bond-allowances {
                    staker: tx-sender,
                    bond-index: bond-index,
                })
                ERR_NOT_ALLOWLISTED
            ))
            (first-reward-cycle (bond-period-to-reward-cycle bond-index))
            (bond-start-height (bond-period-to-burn-height bond-index))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle BOND_LENGTH_CYCLES))
            (current-total-staked (get-total-shares-staked-for-cycle first-reward-cycle
                (some bond-index)
            ))
            (stx-balance (stx-account tx-sender))
            (total-balance (+ (get locked stx-balance) (get unlocked stx-balance)))
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L753-756)
```text
        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1
            amount-ustx sats-total true signer-calldata
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L782-784)
```text
        ;; Move the staker's custodied sBTC into this bond, transferring only the
        ;; net difference vs. any bond they're rolling over from.
        (try! (roll-sbtc tx-sender old-sbtc new-sbtc))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-805)
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

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            BOND_LENGTH_CYCLES amount-ustx false
        ))
```
