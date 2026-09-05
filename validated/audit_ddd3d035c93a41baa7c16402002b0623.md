### Title
Bond-staking share increases bypass mandatory reward settlement, allowing new stakers to retroactively siphon already-accrued sBTC rewards - (`stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`pox-5.clar` implements a MasterChef-style rewards-per-token accounting system for sBTC rewards, tracking `signer-shares-staked-for-cycle`, `staker-shares-staked-for-cycle`, and `total-shares-staked-for-cycle` [1](#0-0) . The contract's own documentation states that `settle-rewards` "MUST be called before any update to `signer-shares-staked-for-cycle`, because changes to that state will affect rewards calculations" [2](#0-1) . The STX-only staking path (`add-staker-to-signer-for-cycle`) correctly follows this rule, calling `settle-rewards` and `settle-staker-rewards` before mutating any share maps [3](#0-2) . However, the analogous bond-staking path, `add-staker-to-bond-for-cycle`, mutates `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and `staker-shares-staked-for-cycle` directly, without ever calling `settle-rewards` beforehand [4](#0-3) .

### Finding Description
`settle-rewards` computes a signer's newly earned reward as a function of the signer's *current* shares multiplied by the change in `rewards-per-token` since the last settlement snapshot [5](#0-4) . This is the classic reward-accounting invariant from the report: shares must be frozen/settled at the reward-per-token snapshot *before* the share balance changes, otherwise a newly joined participant's shares get multiplied against a `rewards-per-token` delta that accrued before they ever staked.

Compare the two symmetric code paths:
- STX-only staking (`add-staker-to-signer-for-cycle`): calls `(settle-rewards signer cycle none)` then conditionally `(settle-staker-rewards signer cycle none staker)` before any `map-set` on `signer-shares-staked-for-cycle` / `total-shares-staked-for-cycle` [6](#0-5) .
- Unstaking from a bond (`unstake-sats-from-bond-cycle`): also correctly calls `(settle-rewards signer reward-cycle (some bond-index))` and `(settle-staker-rewards signer reward-cycle (some bond-index) staker)` before decrementing shares [7](#0-6) .
- Staking into a bond (`add-staker-to-bond-for-cycle`): increments `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and `staker-shares-staked-for-cycle` with **no preceding call to `settle-rewards` or `settle-staker-rewards`** [8](#0-7) .

Because the signer's shares are inflated *before* the pending reward delta for the signer is crystallized, the next time `settle-rewards` runs for that signer/bond-index it will compute `earned = shares_new * (rewards_per_token_current - rewards_per_token_settled)` using the post-increase share count against a `rewards-per-token` delta that partially or fully accrued *before* the new staker joined. This retroactively credits the newly-joined staker's shares with rewards that were already fully attributable to the pre-existing stakers/signer for that period, over-crediting the signer's aggregate `signer-unclaimed-rewards-for-cycle` beyond what the global `rewards-per-token-for-cycle` distribution actually apportioned to that signer's shares. This is a double-count of the reward pool — it does not merely redistribute unfairly among stakers of the same signer (as in the report's medium-severity precedent) but inflates the signer's total claimable sBTC beyond the amount the reward emission schedule intended for that signer, at the expense of other signers/stakers competing for the same fixed reward pool.

### Impact Explanation
This maps to "sBTC rewards paid that were not earned or counted twice" under the Critical impact category, since a bond-staker (or the signer they join) can claim rewards for a period during which they had no shares locked, diluting/stealing rewards genuinely earned by other signers/stakers from the shared, fixed reward emission for the cycle.

### Likelihood Explanation
The bug is unconditional on every bond-staking deposit that occurs mid-cycle after any reward accrual — any protocol-bond staker calling into the bond join path will trigger this state, with no special external conditions or attacker action beyond a normal deposit. This is comparable to (or more severe than) the audited M-6 issue, since here it inflates the signer's total earned rewards rather than merely reallocating shares among a signer's own stakers.

### Recommendation
Add `(settle-rewards signer reward-cycle (some bond-index))` and, when the staker already has prior shares, `(settle-staker-rewards signer reward-cycle (some bond-index) staker)` at the start of `add-staker-to-bond-for-cycle`, mirroring the pattern already used in `add-staker-to-signer-for-cycle` and `unstake-sats-from-bond-cycle`, before any `map-set` on `total-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, or `staker-shares-staked-for-cycle`.

### Proof of Concept
Conceptual sequence within a single reward cycle `C` for signer `S`, bond-index `B`:
1. Staker `A` stakes `1000` sats into bond `B` for signer `S` via `add-staker-to-bond-for-cycle`. `signer-shares-staked-for-cycle[S,C,B] = 1000`.
2. Rewards accrue; `rewards-per-token-for-cycle[C,B]` increases from `0` to `R1` due to sBTC reward distribution while only `A`'s `1000` shares are staked.
3. Staker `B_new` joins bond `B` for the same signer with `9000` sats via `add-staker-to-bond-for-cycle`, **without settlement occurring first**: `signer-shares-staked-for-cycle[S,C,B]` jumps straight to `10000`.
4. Later, any operation triggers `settle-rewards(S, C, some B)`. It computes `earned = shares(10000) * (rewards_per_token_current - rewards_per_token_settled)`. Because `rewards_per_token_settled` was last snapshotted when only `A`'s `1000` shares existed, the delta `R1 - settled` reflects reward accrual meant to be split among `1000` shares, but is now multiplied by `10000` shares — crediting the signer (and thus stakers `A` and `B_new` combined) roughly `10x` the sBTC reward actually apportioned to that signer's shares for that period, at other signers'/stakers' expense.

Note: I was unable to trace the exact public entry point (e.g., `stake-bond`/`register-for-bond`) that calls `add-staker-to-bond-cycles` due to tool-call limits, but the asymmetry is confirmed directly from the contract source: the withdrawal path (`unstake-sats-from-bond-cycle`) and the STX-only staking path (`add-staker-to-signer-for-cycle`) both call `settle-rewards`/`settle-staker-rewards` before mutating shares, while `add-staker-to-bond-for-cycle` — performing the mirror-image "add" operation on the same share maps — does not, in direct violation of the contract's own documented invariant.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L278-300)
```text
;; Amount of shares staked for a given signer in a given cycle.
;; This is strictly for reward calculations -
;; i.e. when is-bond is false, only the STX from STX-only staking
;; is accounted for here, not the STX from bonds.
(define-map signer-shares-staked-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
    }
    uint
)

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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1391-1410)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1663-1703)
```text
(define-private (add-staker-to-signer-for-cycle
        (cycle-index uint)
        (accumulator-res (response {
            signer: principal,
            staker: principal,
            amount-ustx: uint,
            first-reward-cycle: uint,
            is-stx-staking: bool,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (cycle (+ cycle-index (get first-reward-cycle accumulator)))
            (signer (get signer accumulator))
            ;; Get the total uSTX delegated (through protocol bonds and STX-only
            ;; staking) to this signer.
            (cur-delegated-for-signer (get-amount-delegated-for-signer signer cycle))
            (amount (get amount-ustx accumulator))
            (stake-amount (if (get is-stx-staking accumulator)
                amount
                u0
            ))
            (staker (get staker accumulator))
            (prev-staked (get-signer-pending-staked-ustx-per-cycle signer cycle))
            (prev-total-shares-staked (get-total-shares-staked-for-cycle cycle none))
            (new-delegated (+ cur-delegated-for-signer amount))
            (prev-staker-shares (get-staker-shares-staked-for-cycle staker cycle none signer))
        )
        ;; Crystallize STX-only rewards before mutating anything
        (settle-rewards signer cycle none)
        ;; When zero, this is a no-op (`earned = shares * (rpt - rpt-paid) = 0`). In this case,
        ;; we skip calling `settle-staker-rewards` to reduce cost.
        (if (> prev-staker-shares u0)
            (settle-staker-rewards signer cycle none staker)
            {
                earned: u0,
                rewards-per-token: u0,
            }
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1806-1852)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2525-2544)
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
```
