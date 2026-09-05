Found the analog. `stake-update` in `pox-5.clar` mutates the staker's per-cycle share bookkeeping (`remove-staker-from-cycles` / `add-staker-to-signer-cycles`) without calling `settle-rewards` / `settle-staker-rewards` first — unlike every other mutating entry point in the same contract (`register-for-bond`, `update-bond-registration`, `announce-l1-early-exit`) which explicitly call these settlement functions "before updating state"/"before mutating related state".

### Title
Missing reward settlement before share mutation in `stake-update()` allows reward loss/double-count via reward-cycle rewrite - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`stake-update()` lets a staker change signer, extend lock length, and increase locked STX in one call. To do this it tears down the staker's current-and-future per-cycle share records with `remove-staker-from-cycles` and rebuilds them with `add-staker-to-signer-cycles` using a (possibly different) `signer` and a new `new-lock-amount`, then overwrites `staker-info`. [1](#0-0) . Nowhere in this function is `settle-rewards` or `settle-staker-rewards` invoked, in contrast to `register-for-bond` and `update-bond-registration`, both of which explicitly call `settle-rewards`/`settle-staker-rewards` immediately before performing an equivalent teardown/rebuild of cycle-share state. [2](#0-1) [3](#0-2) 

### Finding Description
Rewards in pox-5 are computed via a MasterChef-style accumulator: `rewards-per-token-for-cycle`, with a staker's/signer's pending reward being `(rewards-per-token-for-cycle - staker/signer-rewards-per-token-settled-for-cycle) * shares`. `settle-rewards`/`settle-staker-rewards` snapshot this accumulator into `signer-rewards-per-token-settled-for-cycle` / `staker-rewards-per-token-settled-for-cycle` and move the delta into `signer-unclaimed-rewards-for-cycle` / `staker-unclaimed-rewards-for-cycle`, so that changing `shares` afterward doesn't retroactively affect rewards already accrued at the old share amount. [4](#0-3) 

`stake-update` changes `amount-ustx` (the staker's shares) for `first-reward-cycle` onward and can also change `signer` via `remove-staker-from-cycles`/`add-staker-to-signer-cycles`, but it does this without first calling `settle-rewards`/`settle-staker-rewards` for the affected signer(s)/cycles, unlike `register-for-bond` (line 773-776) and `update-bond-registration` (line 895-901), which do call these settlement functions right before their analogous `remove-staker-from-cycles`/`add-staker-to-signer-cycles` sequences (lines 786-919/904-919). This is exactly the GClaimManager `join()` pattern: a function pulls/mutates a balance that depends on an accumulator (`target`/`rewards-per-token`) that should have been "collected"/"settled" first, but isn't, so subsequent computations use stale per-share settlement snapshots against a newly mutated share amount.

Concretely, `staker-rewards-per-token-settled-for-cycle` for the *current* cycle is keyed by `{reward-cycle, bond-index, signer, staker}`. If a staker calls `stake-update` mid-cycle to switch `signer`, the old signer's per-cycle entry is torn down via `remove-staker-from-cycles` without settling first — meaning any `rewards-per-token` delta accrued between the last settlement and this call for the old signer is not captured into `staker-unclaimed-rewards-for-cycle`/`signer-unclaimed-rewards-for-cycle` before the share record disappears. Because `get-earned-staker-rewards`/`claim-staker-rewards` compute earned rewards from `(current rewards-per-token - settled snapshot) * shares`, and the settled-snapshot map entry is keyed to the now-removed `signer`, the previously-earned (but unsettled) rewards for that signer/cycle become permanently unreachable — a freezing of that portion of the reward, since no future settlement call is keyed to read it. Conversely, because `amount-increase` shares are added at `new-lock-amount` beginning at `first-reward-cycle` without settling first at the pre-increase share level, if any reward event happens in the same cycle between the increase and settlement, the increased shares could retroactively multiply against an unsettled reward delta for the whole cycle, effectively over-crediting rewards proportional to `amount-increase`, i.e. double counting a portion of the cycle's rewards relative to actual time-weighted stake.

### Impact Explanation
This falls under "temporary freezing of staked funds" / "double-counting a commitment or reward" territory (High/Critical) because it breaks the equality between `sum(rewards-per-token deltas * shares over the periods shares were actually held)` and the amount ultimately claimable, either freezing a staker's rightfully-earned sBTC reward share (unreachable due to signer-key mismatch on the settled-snapshot map) or letting a staker claim rewards computed against a higher share count than was actually staked for part of the cycle, at the expense of the reserve/other stakers.

### Likelihood Explanation
Likelihood is moderate: it requires a staker who has already staked, is not in the prepare phase, and calls `stake-update` (a normal user-facing action) mid-cycle after a reward-affecting event (an sBTC transfer + `calculate-rewards` call) has already changed `rewards-per-token-for-cycle` for that cycle. `calculate-rewards`/reward distribution appears to be routinely triggered (as shown by test flows), so an ordinary `stake-update` call could unintentionally trigger this — no privileged role is required, only the staker's own unprivileged call sequence.

### Recommendation
In `stake-update`, call `settle-rewards` and `settle-staker-rewards` for the staker's current `signer`/`bond-index: none` and current cycle (mirroring `update-bond-registration`'s pattern at lines 895-901) before invoking `remove-staker-from-cycles` and `add-staker-to-signer-cycles`, so that any pending reward delta is snapshotted into `*-unclaimed-rewards-for-cycle` against the correct signer/shares before those records are torn down and rebuilt.

### Proof of Concept
1. Alice stakes via `stake()` STX to `signer-A` for `num-cycles` cycles; `first-reward-cycle = N`. [5](#0-4) 
2. In cycle N, an sBTC reward is deposited and `calculate-rewards` runs, bumping `rewards-per-token-for-cycle` for `signer-A`/cycle N. Alice's earned-but-unsettled reward accrues against her current shares under `signer-A`.
3. Alice calls `stake-update` switching to `signer-B` (or just increasing `amount-increase`) before ever calling a settlement path for `signer-A`/cycle N. `remove-staker-from-cycles` deletes her `signer-A` share record for cycle N and `add-staker-to-signer-cycles` creates a fresh `signer-B` record, all without invoking `settle-rewards`/`settle-staker-rewards`. [1](#0-0) 
4. Because `staker-rewards-per-token-settled-for-cycle` is keyed by `signer`, the unsettled delta accrued under `signer-A` for cycle N is never captured into `staker-unclaimed-rewards-for-cycle` for `signer-A`, and no live share record under `signer-A` remains to re-derive it later — that reward becomes permanently unclaimable, while under `signer-B` her rewards for the remainder of cycle N are computed as if she held `new-lock-amount` shares under `signer-B` for the entire cycle, which double-counts relative to actual time held.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L291-333)
```text
;; Represents a snapshot of `rewards-per-token` at the last
;; time of rewards settlement for this specific signer
(define-map signer-rewards-per-token-settled-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
    }
    uint
)

;; Represents pending, but unclaimed rewards for a signer
(define-map signer-unclaimed-rewards-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
    }
    uint
)

;; Represents a snapshot of `rewards-per-token` at the last
;; time of rewards settlement for this specific staker
(define-map staker-rewards-per-token-settled-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
        staker: principal,
    }
    uint
)

;; Represents pending, but unclaimed rewards for a staker
(define-map staker-unclaimed-rewards-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
        staker: principal,
    }
    uint
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L772-776)
```text
        ;; Settle rewards before updating state
        (settle-rewards signer first-reward-cycle (some bond-index))
        (settle-staker-rewards signer first-reward-cycle (some bond-index)
            tx-sender
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L895-901)
```text
        ;; Settle rewards before mutating related state
        (settle-rewards current-signer current-cycle (some bond-index))
        (settle-rewards signer current-cycle (some bond-index))
        (settle-staker-rewards current-signer current-cycle (some bond-index)
            tx-sender
        )
        (settle-staker-rewards signer current-cycle (some bond-index) tx-sender)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L976-1065)
```text
(define-public (stake
        (signer-manager <signer-manager-trait>)
        (amount-ustx uint)
        (num-cycles uint)
        (start-burn-ht uint)
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
            (current-cycle (current-pox-reward-cycle))
            (first-reward-cycle (+ u1 current-cycle))
            (specified-reward-cycle (+ u1 (burn-height-to-reward-cycle start-burn-ht)))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle num-cycles))
            ;; Any bond the staker is currently a member of. Some value here
            ;; indicates this `stake` is a roll-over from an ending bond into
            ;; STX-only.
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
            ;; sBTC currently custodied for the staker's existing bond (0 if
            ;; they have none, or if the existing bond is an L1 lock). On a
            ;; bond-to-stake rollover the full custody is refunded below.
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            (stx-balance (stx-account tx-sender))
            (total-balance (+ (get locked stx-balance) (get unlocked stx-balance)))
        )
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender
            first-reward-cycle num-cycles amount-ustx u0 false
            signer-calldata
        ))

        ;; The signer must have been registered already, and its signer key
        ;; grant must still be active.
        (try! (verify-signer-key-grant signer
            (unwrap! (get-signer-info signer) ERR_SIGNER_NOT_FOUND)
        ))

        ;; the start-burn-ht must result in the next reward cycle, do not allow stakers
        ;;  to "post-date" their transaction
        (asserts! (is-eq first-reward-cycle specified-reward-cycle)
            ERR_INVALID_START_BURN_HEIGHT
        )

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        ;; Cannot already be STX-only staking. Re-extending an existing stake
        ;; goes through `stake-update`, not a second `stake` call.
        (asserts! (is-none (get-staker-info tx-sender)) ERR_ALREADY_STAKED)

        ;; A roll-over from an existing bond is allowed when the bond's term
        ;; ends no later than this stake's first reward cycle. Already-active
        ;; bonds are rejected (overlap). Same shape as the
        ;; `register-for-bond` gate.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_STAKED
        )

        ;; A roll-over from an ending bond may only happen once that bond's
        ;; L1 collateral would have unlocked -- the same window an L1 bond
        ;; holder has to redirect their BTC. Keeps parity with the
        ;; `register-for-bond` gate so a bond's STX / sBTC can't be released
        ;; ahead of the bond's L1 unlock height.
        (try! (verify-bond-rollover-window existing-membership))

        ;;  the Staker must have sufficient total funds (locked + unlocked).
        ;;  On a roll-over the staker's STX is still locked by the ending
        ;;  bond; the node-side handler extends that lock to the new amount,
        ;;  so checking only `stx-get-balance` (unlocked) would falsely fail.
        (asserts! (>= total-balance amount-ustx) ERR_INSUFFICIENT_STX)

        ;; Refund any sBTC custodied for the rolled-over bond (zero-target
        ;; net transfer). No-op when there is no existing bond, or when the
        ;; existing bond is an L1 lock.
        (try! (roll-sbtc tx-sender old-sbtc u0))

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            num-cycles amount-ustx true
        ))

        (map-set staker-info tx-sender {
            amount-ustx: amount-ustx,
            first-reward-cycle: first-reward-cycle,
            num-cycles: num-cycles,
            signer: signer,
        })
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1141-1156)
```text
        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender (+ u1 current-cycle)
            (- prev-unlock-cycle current-cycle u1) true
        ))

        (try! (add-staker-to-signer-cycles tx-sender signer (+ u1 current-cycle)
            num-cycles new-lock-amount true
        ))

        (map-set staker-info tx-sender {
            amount-ustx: new-lock-amount,
            first-reward-cycle: (get first-reward-cycle current-info),
            num-cycles: (+ (get num-cycles current-info) cycles-to-extend),
            signer: signer,
        })

```
