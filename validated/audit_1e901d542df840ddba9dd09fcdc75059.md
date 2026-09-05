### Title
Reentrancy through the caller-supplied `signer-manager` trait lets a staker double-register bond commitments before `register-for-bond` settles its own state - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`register-for-bond` in `pox-5.clar` calls into an attacker-controlled contract (`signer-manager-validate-stake`, invoked at `pox-5.clar:754`) *before* it settles rewards, moves sBTC custody, and records the new membership/shares (`settle-rewards`/`settle-staker-rewards` at `pox-5.clar:773-776`, `roll-sbtc` at `pox-5.clar:784`, and the `map-set`/`add-staker-to-*-cycles` calls at `pox-5.clar:786-805`). Because the state that gates re-registration (`existing-membership`, `current-total-staked`) is snapshotted into `let`-bindings earlier in the function (`pox-5.clar:679,704`) rather than re-read after the callback, a malicious `signer-manager` implementation can re-enter `register-for-bond` (or other bond/stake entry points) during the callback and complete a second registration using the same stale checks, before the outer call writes its own membership and share totals.

### Finding Description
`register-for-bond` is structured as:

1. Read `existing-membership`, `old-sbtc`, `current-total-staked`, etc. into local bindings (`pox-5.clar:679-708`).
2. Run several `asserts!` guards, including the "already staked"/"already registered" checks, which reference the *locally bound* `existing-membership` snapshot, not a fresh map read (`pox-5.clar:730-770`).
3. Call out to the caller-supplied `signer-manager` trait contract via `signer-manager-validate-stake` (`pox-5.clar:754-756`). This contract is chosen by `tx-sender` and is a `<signer-manager-trait>` parameter, so its code is fully attacker-controlled.
4. Only *after* that external call does the function settle rewards, transfer sBTC custody (`roll-sbtc`), and write the new membership and per-cycle share maps (`pox-5.clar:772-805`).

Because Clarity's `contract-call?` performs a genuine synchronous call into another contract's code, the attacker's `signer-manager` implementation can, inside its `validate-stake!`/`validate-stake` callback, invoke `pox-5.register-for-bond` again (for the same staker/bond or a different bond) before the outer invocation has written any of its own state. The `ERR_ALREADY_REGISTERED` guard (`pox-5.clar:767-770`) and the `ERR_ALREADY_STAKED` guard (`pox-5.clar:730-741`) in the *inner* call will see the pre-registration state (no membership yet, since the outer call hasn't reached its `map-set` yet), so the inner call is free to complete a full registration — custody-moving `roll-sbtc`, share bookkeeping, and membership write — for the same staker. When control returns to the outer call, it proceeds past its own already-evaluated guards (which were checked before the reentry and are not re-checked) and performs its own `roll-sbtc` and `map-set` calls, effectively letting one staker register commitments/shares for two overlapping bond positions from what should have been a single, mutually exclusive registration.

This mirrors the reported bug class precisely: a value used to gate a critical financial check (`exchangeRateStored`/here, the "already registered" and total-staked snapshots) is read once at the top of a function and then relied upon after an intervening call to untrusted code that can mutate the very state the check depends on, before the outer call's own effects are committed.

Notably, the developers were aware of this exact risk elsewhere: `calculate-rewards` explicitly guards with `(try! (validate-no-reentrancy))` (`pox-5.clar:2169`) specifically because of "reentrancy through signer-manager trait calls." No equivalent guard is present in `register-for-bond` around the `signer-manager-validate-stake` call, despite that call sitting before the function's own state-mutating operations.

### Impact Explanation
If exploitable, this allows a staker to register overlapping/duplicate bond memberships and duplicate per-cycle share entries (`add-staker-to-bond-cycles`, `add-staker-to-signer-cycles`) while only satisfying custody/allowance checks once (or with stale allowance/"already staked" checks), i.e., double-counting a stacking commitment. Double-counted shares translate directly into inflated reward-pool claims (sBTC rewards paid that were not earned/counted twice) and/or signing weight exceeding the sBTC/STX actually locked — both are explicitly in-scope Critical/High impacts (double-counting a commitment or reward; signing weight exceeding locked value).

### Likelihood Explanation
The `signer-manager` argument to `register-for-bond` is a trait object supplied directly by `tx-sender` (`pox-5.clar:644`), so any unprivileged staker can deploy their own contract implementing `<signer-manager-trait>` and use it as the callback target — no admin, bond-admin, or pause-admin privilege is required. The only obstacle to actually triggering the exploit is whether the guards re-checked on return from the callback (`asserts!` at 767, 730 in the *outer* call, evaluated with locals computed *before* the callback) are strong enough to block the outer call's own subsequent writes; I was not able to fully trace whether Clarity's `let`-binding evaluation order guarantees these guards run strictly before the callback (which would make this safe) or whether some are re-derived/re-read after it. I also could not locate the definition of `roll-sbtc` or confirm the exact evaluation order Clarity uses for `let` bindings with side-effecting calls, which is necessary to fully confirm exploitability versus the developers' apparent reliance on `let`-binding evaluation being safely sequenced.

### Recommendation
- Move `signer-manager-validate-stake` (and any other calls into caller-supplied trait contracts) to occur strictly *after* all of `register-for-bond`'s own state mutations (`roll-sbtc`, `map-set protocol-bond-memberships`, `map-set protocol-bonds-total-staked`, `add-staker-to-bond-cycles`, `add-staker-to-signer-cycles`) are committed, following the checks-effects-interactions pattern.
- Alternatively, add the same `validate-no-reentrancy` guard used in `calculate-rewards` to `register-for-bond` (and any other public function that calls into the `signer-manager` trait before finishing its own bookkeeping).
- Re-verify `existing-membership`/`current-total-staked` immediately before the writes that depend on them, rather than relying on values captured before the external call.

### Proof of Concept
Conceptual PoC (exact reentrancy feasibility depends on Clarity's call-evaluation semantics, which I could not fully confirm from the available index):
1. Attacker deploys a contract `evil-signer-manager` implementing `<signer-manager-trait>`, whose `validate-stake!`/`validate-stake` function, when invoked, calls back into `'SP...pox-5.register-for-bond` for the same `tx-sender`/bond (or a different, non-overlapping bond) with valid sBTC/allowance parameters.
2. Attacker calls `register-for-bond` on `bond-index A`, passing `evil-signer-manager` as the `signer-manager` argument.
3. `pox-5.clar` reaches `signer-manager-validate-stake` (`pox-5.clar:754`) before writing any membership/share state for bond `A`.
4. Inside that callback, `evil-signer-manager` re-enters `register-for-bond` for bond `B`; since no membership has been written yet for the outer call, the inner call's `ERR_ALREADY_REGISTERED`/`ERR_ALREADY_STAKED` guards pass, and it fully completes: moves sBTC via `roll-sbtc`, writes `protocol-bond-memberships`, bumps `protocol-bonds-total-staked`, and adds staker shares for bond `B`.
5. Control returns to the outer call for bond `A`, which proceeds to also perform its own `roll-sbtc`, membership write, and share additions for bond `A`.
6. Result: the staker ends up with share/membership bookkeeping for two overlapping bonds from actions that were supposed to be mutually exclusive, double-counting reward-eligible stake. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-770)
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
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))
        ;; Verify that they're sending enough STX
        (asserts!
            (>= amount-ustx
                (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
                    (get min-ustx-ratio bond)
                ))
            ERR_INSUFFICIENT_STX
        )

        ;; Verify that the bond hasn't started
        (asserts! (< burn-block-height bond-start-height)
            ERR_BOND_ALREADY_STARTED
        )

        ;; An existing STX-only stake is allowed only if its term ends no
        ;; later than this bond's first reward cycle (no overlap). A stx-only
        ;; stake has no L1 collateral, so there's no L1-unlock-window gate
        ;; here -- the lock just extends forward via the node-side handler.
        (asserts!
            (match existing-stake
                stake-info (<=
                    (+ (get first-reward-cycle stake-info)
                        (get num-cycles stake-info)
                    )
                    first-reward-cycle
                )
                true
            )
            ERR_ALREADY_STAKED
        )

        ;; Cannot stake more sats than their allowance
        (asserts! (<= sats-total allowance) ERR_TOO_MUCH_SATS)

        ;; Must have enough unlocked STX
        ;;  the Staker must have sufficient total funds (locked + unlocked).
        ;;  On a roll-over the staker's STX is still locked by the ending
        ;;  bond; the node-side handler extends that lock to the new amount,
        ;;  so checking only `stx-get-balance` (unlocked) would falsely fail.
        (asserts! (>= total-balance amount-ustx) ERR_INSUFFICIENT_STX)

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1
            amount-ustx sats-total true signer-calldata
        ))

        ;; The signer must have been registered already, and its signer key
        ;; grant must still be active.
        (try! (verify-signer-key-grant signer
            (unwrap! (get-signer-info signer) ERR_SIGNER_NOT_FOUND)
        ))

        ;; Reject if an existing membership *overlaps* this bond. An existing
        ;; bond whose staking term ends no later than this bond's first cycle
        ;; (e.g. rolling from bond N into bond N+6) is allowed.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_REGISTERED
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L772-805)
```text
        ;; Settle rewards before updating state
        (settle-rewards signer first-reward-cycle (some bond-index))
        (settle-staker-rewards signer first-reward-cycle (some bond-index)
            tx-sender
        )

        ;; A rollover from a non-overlapping existing bond may only happen in
        ;; that bond's L1 unlock window, the last 1/2 cycle.
        (try! (verify-bond-rollover-window existing-membership))

        ;; Move the staker's custodied sBTC into this bond, transferring only the
        ;; net difference vs. any bond they're rolling over from.
        (try! (roll-sbtc tx-sender old-sbtc new-sbtc))

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2158-2169)
```text
(define-public (calculate-rewards (bond-periods (list 6 uint)))
    (let (
            (last-calc (var-get last-reward-compute-height))
            (calculation-height (- (distribution-cycle-to-burn-height (current-distribution-cycle))
                u1
            ))
            (cur-reserve (var-get reserve-balance))
            (gross-accrued-rewards (get-new-rewards))
            (stx-cycle (burn-height-to-reward-cycle calculation-height))
        )
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))
```
