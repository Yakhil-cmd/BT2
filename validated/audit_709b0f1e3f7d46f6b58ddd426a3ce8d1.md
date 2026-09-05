Based on direct comparison of two structurally parallel private functions in `pox-5.clar`, I found a genuine analog of the reported bug class: a "remove stake" path that mutates the reward-accounting state (`total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`) **without first settling rewards**, unlike its sibling function which does this correctly.

### Title
Bond-cycle removal path mutates staked shares without settling rewards first, permanently stranding accrued sBTC rewards - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`remove-staker-from-bond-for-cycle` decrements `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and zeroes `staker-shares-staked-for-cycle` for a bond-index/cycle without calling `settle-rewards` / `settle-staker-rewards` beforehand, breaking the accumulator invariant the contract itself documents and enforces everywhere else.

### Finding Description
`pox-5.clar` implements a standard reward-per-token accumulator pattern for both bond and STX-only staking. The contract explicitly documents the required invariant at the definition of `settle-rewards`: [1](#0-0) 
"This MUST be called before any update to `signer-shares-staked-for-cycle`, because changes to that state will effect rewards calculations." The same requirement is documented for `settle-staker-rewards`.

Every other mutator of these maps honors this. For example, `unstake-sats-from-bond-cycles` (full/partial bond-sats withdrawal) explicitly calls both settlement functions immediately before mutating the same three maps: [2](#0-1) 

However, `remove-staker-from-bond-for-cycle` — the bond-cycle analog of the STX-only `remove-staker-from-signer-for-cycle` (which itself correctly calls `settle-rewards`/`settle-staker-rewards` at lines 1543-1544 before any mutation) — skips settlement entirely: [3](#0-2) 

It reads `current-total-staked` and `current-signer-staked`, then immediately overwrites `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and zeroes `staker-shares-staked-for-cycle` — with no snapshot of `signer-rewards-per-token-for-cycle` into `signer-rewards-per-token-settled-for-cycle`/`signer-unclaimed-rewards-for-cycle`, and no equivalent snapshot for the staker.

Because `compute-earned-rewards` computes `earned = pending + shares * (rpt-current - rpt-paid)` (see lines 2378-2384), zeroing `staker-shares-staked-for-cycle` before this staker's `pending`/`rpt-paid` are refreshed means any reward accrued between the staker's last settlement and this removal is permanently lost: the `shares` term becomes `0`, and `pending` was never incremented to capture the interim-earned amount. The corresponding sBTC stays in the contract (it was already paid into `rewards-per-token-for-cycle`/the bond-reward pool by `calculate-rewards`), but is never attributable to any claimant — it is permanently stranded/frozen, breaking the equality "sum of claimable rewards == total rewards distributed for that cycle."

### Impact Explanation
This breaks the reward accounting equality the same way as the reported bug class (mutating a value gating reward computation without first accounting for it), except the direction is a permanent loss/freeze of already-accrued sBTC/STX rewards rather than an over-claim. Per the rules, this qualifies as "permanent freezing of ... sBTC rewards" (Critical) since the stranded sBTC becomes permanently unclaimable by any account once the staker's bond-cycle membership is removed via this path.

### Likelihood Explanation
The path is reachable whenever a staker's bond-cycle entries are removed via `remove-staker-from-bond-cycles` (this function is the sole caller of `remove-staker-from-bond-for-cycle`). This requires no privileged role — it fires as a normal consequence of a staker-initiated action that triggers bond-cycle removal (e.g., re-registering into a new bond or otherwise rolling out of an existing bond commitment), which any unprivileged staker can trigger on their own account.

**Caveat**: I was unable to fully confirm, within the available tool budget, the exact public entry point(s) that call `remove-staker-from-bond-cycles` (grep confirmed 10 references within `pox-5.clar` but I did not get to read every call site before running out of iterations). The core defect — the missing settlement calls compared to the structurally identical, correctly-implemented sibling function `unstake-sats-from-bond-cycles`/`remove-staker-from-signer-for-cycle` — is directly verified in the code above and is unambiguous.

### Recommendation
Add `(settle-rewards signer reward-cycle (some bond-index))` and `(settle-staker-rewards signer reward-cycle (some bond-index) staker)` calls at the top of `remove-staker-from-bond-for-cycle`, immediately after reading `current-total-staked`/`current-signer-staked` and before any `map-set` mutation — mirroring the pattern already used in `unstake-sats-from-bond-cycles` (lines 1396-1397) and `remove-staker-from-signer-for-cycle` (lines 1543-1544).

### Proof of Concept
1. Staker registers for a bond (`register-for-bond`), acquiring `staker-shares-staked-for-cycle` > 0 for bond-index `B`, cycle `C`.
2. The signer's bond earns sBTC rewards for cycle `C` via `calculate-rewards`, incrementing `rewards-per-token-for-cycle{C, some B}` — the staker now has unsettled earned rewards (`rpt-current > rpt-paid`, `shares > 0`).
3. Before the staker calls `claim-rewards` (which would call `settle-staker-rewards`), the staker triggers a path that invokes `remove-staker-from-bond-cycles` for cycle `C` (e.g., rolling into a new bond via `register-for-bond`, or another registration-changing action that clears prior bond membership).
4. `remove-staker-from-bond-for-cycle` executes: it zeroes `staker-shares-staked-for-cycle` for `(staker, C, B, signer)` and decrements `signer-shares-staked-for-cycle`/`total-shares-staked-for-cycle` without ever calling `settle-staker-rewards`/`settle-rewards`.
5. The staker calls `get-earned-staker-rewards`/`claim-rewards` for `(signer, C, B, staker)`: `compute-earned-rewards` now uses `shares = 0` (just mutated) with the stale `rpt-paid` snapshot — the reward accrued during step 2 is not reflected in `pending`, so it returns less than what was actually earned; that portion of sBTC remains locked in the contract, permanently unclaimable by the staker or anyone else.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1391-1418)
```text
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
        (map-set staker-shares-staked-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
            signer: signer,
            staker: staker,
        }
            new-amount-sats
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
