### Title
Bond removal zeroes staker's bond shares without settling accrued rewards, causing permanent loss of unclaimed sBTC rewards - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`remove-staker-from-bond-for-cycle` in `pox-5.clar` mutates `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and zeroes the staker's `staker-shares-staked-for-cycle` entry without first calling `settle-rewards`/`settle-staker-rewards`, unlike the sibling function `unstake-sats-from-bond-cycle` which explicitly settles rewards before mutating the same state.

### Finding Description
The contract's reward accounting relies on a MasterChef-style "settle-then-mutate" pattern: any change to `signer-shares-staked-for-cycle` or `staker-shares-staked-for-cycle` must be preceded by a call to `settle-rewards`/`settle-staker-rewards`, because those functions snapshot `earned = shares * (rpt - rpt-paid) + pending` into `signer-unclaimed-rewards-for-cycle` / `staker-unclaimed-rewards-for-cycle` using the *current* (pre-mutation) share count and reward-per-token index. This invariant is explicitly documented at `settle-rewards` and `settle-staker-rewards`: "This MUST be called before any update to `signer-shares-staked-for-cycle` [or `staker-shares-staked-for-cycle`], because changes to that state will affect rewards calculations." [1](#0-0) 

The function `unstake-sats-from-bond-cycle` correctly follows this pattern: it calls `(settle-rewards signer reward-cycle (some bond-index))` and `(settle-staker-rewards signer reward-cycle (some bond-index) staker)` immediately before decrementing `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and (implicitly) the staker's share balance. [2](#0-1) 

However, `remove-staker-from-bond-for-cycle` — which performs the analogous operation of decrementing `total-shares-staked-for-cycle`, decrementing `signer-shares-staked-for-cycle`, and zeroing `staker-shares-staked-for-cycle` to `u0` for a given reward cycle/bond-index — does **not** call `settle-rewards` or `settle-staker-rewards` at all before performing these mutations. [3](#0-2) 

Once `staker-shares-staked-for-cycle` is zeroed without a prior settlement, any rewards accrued between the staker's last settlement point (their `staker-rewards-per-token-settled-for-cycle` snapshot) and the current `rewards-per-token-for-cycle` for that cycle/bond are computed from `compute-earned-rewards` using the staker's shares — but since the shares are now `u0` in storage and no `earned` pending amount was ever recorded via `settle-staker-rewards`, that delta is permanently unrecoverable. This is the exact analog of the Ajna `PositionManager.memorializePositions` bug: state that gates reward-claim eligibility (share count / LP balance) is zeroed out by a bookkeeping path that is decoupled from the reward-settlement mechanism, silently discarding rewards the user had already earned but not yet claimed.

### Impact Explanation
This causes a temporary/permanent freezing (loss) of sBTC bond rewards that the staker had legitimately earned in a bond cycle but had not yet claimed, whenever `remove-staker-from-bond-for-cycle` runs on their entry without a preceding settlement. This falls under "temporary freezing of staked funds" / loss-of-reward class of High severity, since the value lost is the staker's own accrued (unbacked-by-claim) sBTC reward, not an attacker's own stake, and it is unintentionally destroyed by protocol code rather than by a user error.

### Likelihood Explanation
Likelihood depends on how often `remove-staker-from-bond-cycles`/`remove-staker-from-bond-for-cycle` is invoked relative to reward accrual for the affected reward cycle — this is a pure bookkeeping-path inconsistency (present regardless of attacker action) rather than something requiring a privileged party, so it will trigger whenever the code path executes on a staker that has unsettled rewards for that cycle/bond-index.

### Recommendation
Add `(settle-rewards signer reward-cycle (some bond-index))` and `(settle-staker-rewards signer reward-cycle (some bond-index) staker)` at the top of `remove-staker-from-bond-for-cycle`, mirroring `unstake-sats-from-bond-cycle`, before mutating `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and `staker-shares-staked-for-cycle`.

### Proof of Concept
1. Staker joins a bond cycle via `add-staker-to-bond-for-cycle`, acquiring nonzero `staker-shares-staked-for-cycle` and a `staker-rewards-per-token-settled-for-cycle` snapshot at time T0.
2. `rewards-per-token-for-cycle` for that signer/bond-index increases (rewards accrue) between T0 and T1.
3. Some code path calls `remove-staker-from-bond-cycles` → `remove-staker-from-bond-for-cycle` for the staker at T1 (e.g., as part of bond exit/removal bookkeeping), which sets `staker-shares-staked-for-cycle` to `u0` directly, without invoking `settle-staker-rewards`.
4. `staker-unclaimed-rewards-for-cycle` was never updated to reflect the shares×Δrpt earned between T0 and T1, and the shares are now zero, so `get-earned-staker-rewards`/`claim-rewards`-style computation for that staker/cycle can no longer recover the accrued-but-unsettled delta — the reward is permanently lost. [3](#0-2) [4](#0-3)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1364-1410)
```text
;; Reduce (or remove) a staker's bond shares for a given cycle.
;; For the provided cycle, the signer is derived from `staker-signer-cycle-memberships`.
;; Rewards are settled for this cycle before mutating state.
;; Finally, cycle stake state is updated.
(define-private (unstake-sats-from-bond-cycle
        (cycle-index uint)
        (accumulator-res (response {
            staker: principal,
            bond-index: uint,
            first-reward-cycle: uint,
            amount-to-withdrawal-sats: uint,
            new-amount-sats: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (reward-cycle (+ cycle-index (get first-reward-cycle accumulator)))
            (staker (get staker accumulator))
            (bond-index (get bond-index accumulator))
            (amount-to-withdrawal-sats (get amount-to-withdrawal-sats accumulator))
            (new-amount-sats (get new-amount-sats accumulator))
            (signer (get signer
                (unwrap! (get-signer-cycle-membership staker reward-cycle)
                    ERR_NOT_STAKING
                )))
            (current-total-staked (get-total-shares-staked-for-cycle reward-cycle (some bond-index)))
            (current-signer-staked (get-signer-shares-staked-for-cycle signer reward-cycle
                (some bond-index)
            ))
        )
        (settle-rewards signer reward-cycle (some bond-index))
        (settle-staker-rewards signer reward-cycle (some bond-index) staker)
        (map-set total-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
        }
            (- current-total-staked amount-to-withdrawal-sats)
        )
        (map-set signer-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
        }
            (- current-signer-staked amount-to-withdrawal-sats)
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1887-1936)
```text
(define-private (remove-staker-from-bond-for-cycle
        (cycle-index uint)
        (accumulator-res (response {
            signer: principal,
            staker: principal,
            bond-index: uint,
            amount-sats: uint,
            first-reward-cycle: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (reward-cycle (+ cycle-index (get first-reward-cycle accumulator)))
            (signer (get signer accumulator))
            (bond-index (get bond-index accumulator))
            (amount-sats (get amount-sats accumulator))
            (current-total-staked (get-total-shares-staked-for-cycle reward-cycle (some bond-index)))
            (current-signer-staked (get-signer-shares-staked-for-cycle signer reward-cycle
                (some bond-index)
            ))
        )
        ;;  Update total shares staked for this cycle
        (map-set total-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
        }
            (- current-total-staked amount-sats)
        )
        ;;  Update total shares for this signer
        (map-set signer-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
        }
            (- current-signer-staked amount-sats)
        )
        ;;  Update staker's shares
        (map-set staker-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
            staker: (get staker accumulator),
        }
            u0
        )
        (ok accumulator)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2525-2530)
```text
;; Update all earned-but-unclaimed rewards for a signer, and update the snapshot
;; (signer-rewards-per-token-settled-for-cycle) for the signer.
;;
;; This MUST be called before any update to `signer-shares-staked-for-cycle`,
;; because changes to that state will effect rewards calculations.
(define-private (settle-rewards
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2576-2600)
```text
;; Update all earned-but-unclaimed rewards for a staker, and update the snapshot
;; (staker-rewards-per-token-settled-for-cycle) for the staker.
;;
;; This MUST be called before any update to `staker-shares-staked-for-cycle`,
;; because changes to that state will effect rewards calculations.
(define-private (settle-staker-rewards
        (signer principal)
        (reward-cycle uint)
        (bond-index (optional uint))
        (staker principal)
    )
    (let (
            (earned (get-earned-staker-rewards signer reward-cycle bond-index staker))
            (rewards-per-token (get-signer-rewards-per-token-for-cycle signer reward-cycle
                bond-index
            ))
        )
        (map-set staker-unclaimed-rewards-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
            signer: signer,
            staker: staker,
        }
            earned
        )
```
