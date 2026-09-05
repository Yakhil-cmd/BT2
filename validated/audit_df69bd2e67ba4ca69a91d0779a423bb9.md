### Title
Signer/staker sBTC-bond shares are mutated without settling pending rewards first, causing incorrect reward distribution - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`pox-5.clar` tracks per-signer and per-staker sBTC reward accrual with a reward-per-token accumulator pattern (`rewards-per-token-for-cycle`), settled via `settle-rewards`/`settle-staker-rewards`. The contract's own documentation states this settlement **MUST** happen before any change to `signer-shares-staked-for-cycle` [1](#0-0) , and the sibling functions `unstake-sats-from-bond-cycle` and `remove-staker-from-signer-for-cycle` correctly do this [2](#0-1) [3](#0-2) . However, `add-staker-to-bond-for-cycle` and `remove-staker-from-bond-for-cycle` mutate `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and `staker-shares-staked-for-cycle` directly, without ever calling `settle-rewards`/`settle-staker-rewards` first [4](#0-3) [5](#0-4) . This is directly analogous to the reported "outdated interest rate" bug class: state variables used by a rate/reward computation (`compute-earned-rewards` at [6](#0-5) ) are read and relied upon downstream while the underlying shares have already been mutated out from under a stale, un-settled snapshot.

### Finding Description
Reward accounting for both signers and stakers uses the standard "rewards-per-token" pattern:
```
earned = pending + shares * (rpt_current - rpt_paid) / PRECISION
```
`settle-rewards`/`settle-staker-rewards` freeze `earned` and set `rpt_paid = rpt_current` for a given `(signer/staker, cycle, bond-index)` [7](#0-6) . The comment above `settle-rewards` explicitly states: *"This MUST be called before any update to `signer-shares-staked-for-cycle`, because changes to that state will affect rewards calculations."* [1](#0-0) 

Two private helpers violate this invariant:
- `add-staker-to-bond-for-cycle` increments `total-shares-staked-for-cycle` and `signer-shares-staked-for-cycle` for the given cycle/bond, and sets the staker's `staker-shares-staked-for-cycle`/settled snapshot, all *without first calling `settle-rewards`* for that signer/cycle [4](#0-3) .
- `remove-staker-from-bond-for-cycle` decrements the same maps (down to `u0` for the removed staker) *without calling `settle-rewards`/`settle-staker-rewards`* first [5](#0-4) .

Contrast this with the correctly-guarded siblings:
- `unstake-sats-from-bond-cycle`, used by `unstake-sbtc`/`announce-l1-early-exit`, calls `(settle-rewards signer reward-cycle (some bond-index))` and `(settle-staker-rewards ...)` before mutating shares [8](#0-7) .
- `remove-staker-from-signer-for-cycle` also settles before mutating STX-only shares [9](#0-8) .
- `add-staker-to-signer-for-cycle` (the STX-only counterpart of `add-staker-to-bond-for-cycle`) also settles first: *"Crystallize STX-only rewards before mutating anything"* [10](#0-9) .

Because `add-staker-to-bond-for-cycle`/`remove-staker-from-bond-for-cycle` change `signer-shares-staked-for-cycle` while the signer's `signer-rewards-per-token-settled-for-cycle` snapshot is stale, the next `settle-rewards` call computes:
```
earned = new_shares * (rpt_current - rpt_paid)
```
using the *new* (post-mutation) share count against a delta (`rpt_current - rpt_paid`) that actually accrued while the *old* share count was in effect. This breaks the equality that total rewards paid across all signers/stakers for a cycle must equal the rewards actually distributed by `calculate-bond-rewards`/`calculate-rewards` (`rewards-per-token-for-cycle * total-shares`). Depending on direction (increase vs decrease of shares mid-cycle), this either inflates the settling party's earned rewards (double-counting sBTC rewards that were never proportionally earned) or under-credits a removed staker's rightful earned rewards for the pre-removal period (freezing/losing legitimately earned sBTC).

### Impact Explanation
This breaks the core reward-accounting equality for sBTC bond rewards (`sum(earned per signer/staker) == total sBTC distributed for the cycle`), enabling double-counting of sBTC reward entitlement for the party whose shares were freshly added/removed, at the expense of other stakers/signers sharing the same reward pool. This matches the "Critical: double-counting a commitment or reward" / "theft ... of sBTC rewards" impact category, since a staker joining a bond mid-cycle (via whatever registration path invokes `add-staker-to-bond-for-cycle`) can accrue rewards for a period during which their shares were not actually staked, effectively taking sBTC that other legitimate stakers earned.

### Likelihood Explanation
Likelihood is High: the bug is deterministic and triggers any time a staker's bond shares change mid-cycle through `add-staker-to-bond-for-cycle`/`remove-staker-from-bond-for-cycle` while `rewards-per-token-for-cycle` has already advanced from a `calculate-rewards`/`calculate-bond-rewards` call for that cycle (i.e., rewards accrued before the share change). No privileged access is required — it is triggered by ordinary staker actions such as joining or leaving a bond mid-cycle combined with a normal reward-calculation call. Note: I was unable to fully trace, within the remaining tool budget, the exact public entry point(s) (e.g., `register-for-bond` / `update-bond-registration`) that invoke `add-staker-to-bond-cycles`/`remove-staker-from-bond-cycles`, so the precise external call sequence needed to trigger this should be confirmed by a Devin session with full read access to the file, but the missing-settlement defect itself is unambiguous from the code and the contract's own invariant comments.

### Recommendation
Call `settle-rewards` (and, when a specific staker's individual accounting is affected, `settle-staker-rewards`) for the affected `(signer, reward-cycle, bond-index)` at the start of both `add-staker-to-bond-for-cycle` and `remove-staker-from-bond-for-cycle`, mirroring the pattern already used in `unstake-sats-from-bond-cycle` and `remove-staker-from-signer-for-cycle`, before any of the `signer-shares-staked-for-cycle` / `total-shares-staked-for-cycle` / `staker-shares-staked-for-cycle` maps are mutated.

### Proof of Concept
Conceptual sequence (exact public entry points that call these private helpers should be confirmed, but the state-mutation-without-settlement defect is directly visible in the code):
1. Signer `S` has staker `A` staked in bond `B` for cycle `C` with shares `X`.
2. `calculate-rewards`/`calculate-bond-rewards` runs, advancing `rewards-per-token-for-cycle` for `(C, some B)` from `RPT0` to `RPT1`, while `signer-rewards-per-token-settled-for-cycle` for `S` remains at `RPT0` (not yet settled).
3. A new staker joins bond `B` for the same signer `S` in cycle `C`, invoking `add-staker-to-bond-for-cycle`, which increases `signer-shares-staked-for-cycle` for `S` from `X` to `X + Y` — **without** calling `settle-rewards` first [11](#0-10) .
4. A later `settle-rewards` call for `S`/`C`/`some B` computes `earned = (X + Y) * (RPT1 - RPT0)`, crediting rewards for shares `Y` against a reward interval `RPT1 - RPT0` that accrued before `Y` was staked — double-counting rewards that rightfully belonged only to the pre-existing `X` shares, at other stakers'/signers' expense.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1541-1544)
```text
        )
        ;; Settle STX-only rewards before mutating anything
        (settle-rewards signer reward-cycle none)
        (settle-staker-rewards signer reward-cycle none staker)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1691-1698)
```text
            (prev-staker-shares (get-staker-shares-staked-for-cycle staker cycle none signer))
        )
        ;; Crystallize STX-only rewards before mutating anything
        (settle-rewards signer cycle none)
        ;; When zero, this is a no-op (`earned = shares * (rpt - rpt-paid) = 0`). In this case,
        ;; we skip calling `settle-staker-rewards` to reduce cost.
        (if (> prev-staker-shares u0)
            (settle-staker-rewards signer cycle none staker)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1806-1865)
```text
(define-private (add-staker-to-bond-for-cycle
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
        ;; Update total shares staked for this cycle
        (map-set total-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
        }
            (+ current-total-staked amount-sats)
        )
        ;; Update total shares for this signer
        (map-set signer-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
        }
            (+ current-signer-staked amount-sats)
        )
        ;; Update staker's shares
        (map-set staker-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
            staker: (get staker accumulator),
        }
            amount-sats
        )
        ;; Mark settled rewards for this cycle
        (map-set staker-rewards-per-token-settled-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
            staker: (get staker accumulator),
        }
            (get-signer-rewards-per-token-for-cycle signer reward-cycle
                (some bond-index)
            ))
        (ok accumulator)
    )
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2378-2385)
```text
(define-read-only (compute-earned-rewards
        (shares uint)
        (rpt-current uint)
        (rpt-paid uint)
        (pending uint)
    )
    (+ pending (/ (* shares (- rpt-current rpt-paid)) PRECISION))
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2525-2574)
```text
;; Update all earned-but-unclaimed rewards for a signer, and update the snapshot
;; (signer-rewards-per-token-settled-for-cycle) for the signer.
;;
;; This MUST be called before any update to `signer-shares-staked-for-cycle`,
;; because changes to that state will effect rewards calculations.
(define-private (settle-rewards
        (signer principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (let (
            (shares (get-signer-shares-staked-for-cycle signer reward-cycle bond-index))
            (rewards-per-token (get-rewards-per-token-for-cycle reward-cycle bond-index))
            (earned (compute-earned-rewards
                shares
                rewards-per-token
                (get-signer-rewards-per-token-settled-for-cycle signer reward-cycle bond-index)
                (get-signer-unclaimed-rewards-for-cycle signer reward-cycle bond-index)
            ))
        )
        (map-set signer-unclaimed-rewards-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
            signer: signer,
        }
            earned
        )
        (map-set signer-rewards-per-token-settled-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
            signer: signer,
        }
            rewards-per-token
        )
        (if (> shares u0)
            (map-set signer-rewards-per-token-for-cycle {
                signer: signer,
                reward-cycle: reward-cycle,
                bond-index: bond-index,
            }
                rewards-per-token
            )
            true
        )
        {
            earned: earned,
            rewards-per-token: rewards-per-token,
        }
    )
)
```
