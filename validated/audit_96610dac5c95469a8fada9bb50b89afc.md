## Title
Backlogged sBTC rewards attributed only to the single reward-cycle live at `calculate-rewards` time let a staker who joins right before the call capture rewards earned during earlier, already-elapsed cycles - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`calculate-rewards` in pox-5 crystallizes *all* sBTC received since the last computation (`get-new-rewards`, i.e. `current-balance - total-staked-sbtc - reserve`) but assigns the entire backlog to a single `stx-cycle` — the reward cycle containing `calculation-height` at the moment the function happens to be called — rather than splitting it across each reward cycle that actually elapsed while the sBTC accrued. [1](#0-0)  This mirrors the Burve `collectAndCalcCompound()` pattern: value that accrues continuously is only "settled" at a single triggering event, and whoever holds shares at that instant captures the full backlog, disproportionate to how long they actually contributed.

### Finding Description
`calculate-rewards` computes:
- `gross-accrued-rewards = (get-new-rewards)`, the sBTC that piled up since `last-accounted-rewards-only` regardless of how many reward cycles have passed [1](#0-0) 
- `stx-cycle = (burn-height-to-reward-cycle calculation-height)` — a *single* cycle number derived from `current-distribution-cycle` at call time [2](#0-1) 
- `cycle-staked-ustx = (get-total-shares-staked-for-cycle stx-cycle none)` — only the STX-only stake total for that one cycle [3](#0-2) 
- the entire `stx-staker-rewards` cut (after bond yield and reserve) is divided by that single cycle's staked total and written into `rewards-per-token-for-cycle` for `stx-cycle` only [4](#0-3) 

The gate is only "has a new distribution-cycle boundary passed since `last-reward-compute-height`" (`asserts! (> calculation-height last-calc) ERR_DISTRIBUTION_ALREADY_COMPUTED`) [5](#0-4)  — it does not require calling once per half-cycle sequentially, nor does it iterate/backfill missed distribution cycles. If `calculate-rewards` is skipped for one or more distribution-cycle boundaries (it is permissionless, so nothing forces prompt, regular calls — e.g. low activity, no incentive for anyone to pay the fee, or simply irregular usage), all of the sBTC that accrued across those skipped boundaries is dumped into whatever `stx-cycle` happens to be current when someone finally calls it, and split only among the stakers who are recorded in `staker-shares-staked-for-cycle`/`total-shares-staked-for-cycle` for *that* cycle.

Reward-per-token settlement (`settle-rewards` / `settle-staker-rewards`) protects against a staker retroactively claiming rewards *within* a cycle by snapshotting `rewards-per-token` at stake/unstake time before any share change [6](#0-5) . That mechanism only prevents intra-cycle-per-token accounting inconsistency; it does nothing about the cross-cycle backlog problem, because the backlog is attributed at the `calculate-rewards` boundary to whatever cycle is "current" — a staker who is recorded as staked for that cycle (even having joined for that cycle's very start, displacing prior stakers whose cycles already ended and who never got compensated for the sBTC that accrued during their tenure) receives 100% of the multi-cycle backlog.

### Impact Explanation
This breaks the equality "sBTC rewards paid == sBTC rewards actually earned by the stakers who were locked during the period the sBTC accrued." Stakers active during the skipped cycles receive nothing for the sBTC that accrued on their behalf (permanent loss/freezing of earned rewards for them), while stakers only active in the cycle where `calculate-rewards` finally executes receive rewards attributable to periods before they ever staked (theft / double-counting of a reward commitment relative to actual locked-stake duration). Per the rules this falls under High: "theft ... of ... fees" and "signing weight or reward slots exceeding locked value" in effect, since reward entitlement outpaces the staker's actual contribution window.

### Likelihood Explanation
`calculate-rewards` is a permissionless public function with no incentive/requirement to be called every distribution-cycle boundary; the only gate is `calculation-height > last-calc`, so multiple boundaries can trivially be skipped by inaction alone (no privileged action, malicious peer, or special timing manipulation needed beyond simply not calling the function, or an attacker deliberately delaying the call until after joining). An attacker only needs to: (1) observe/ensure `calculate-rewards` hasn't been called in a while while sBTC keeps flowing into the contract, (2) `stake`/`register-for-bond` so they are counted in `total-shares-staked-for-cycle` for the current `stx-cycle`, (3) call or wait for `calculate-rewards`, capturing the whole backlog, then (4) reduce further exposure by scheduling `unstake` shortly after (unstake only reschedules unlock to the next cycle boundary, per `pox_unstake_v5` [7](#0-6) , but the reward capture already happened at `calculate-rewards`).

### Recommendation
Track and distribute rewards per elapsed distribution cycle rather than lumping all `get-new-rewards` into the single `stx-cycle` live at call time — e.g., iterate all distribution-cycle boundaries between `last-reward-compute-height` and the current one, computing `rewards-per-token` separately for each boundary's own `stx-cycle`/`cycle-staked-ustx`, so each cycle's stakers are only credited with the sBTC that genuinely accrued while they were staked.

### Proof of Concept
Conceptual PoC (I could not execute the Vitest/Clarinet suite to empirically confirm the split, so this is derived directly from the contract logic cited above, not from a run trace):
1. Alice stakes `stakeAmount` for cycle N. No one calls `calculate-rewards` while sBTC trickles into the contract for cycles N and N+1.
2. Alice's lock ends / she unstakes at the boundary of N+1 (rewards not yet crystallized, so she has accrued no `rewards-per-token` snapshot for the pending sBTC).
3. Bob stakes at the very start of cycle N+2 (or shortly before someone finally triggers `calculate-rewards` for the boundary landing in N+2).
4. Someone calls `calculate-rewards`. `calculation-height` falls in N+2 (`current-distribution-cycle`), so `stx-cycle = N+2` and `cycle-staked-ustx = total-shares-staked-for-cycle(N+2, none)` — only Bob's stake. The entire `gross-accrued-rewards` (sBTC that accumulated across N, N+1, and N+2) is divided by Bob's stake alone and recorded as `rewards-per-token-for-cycle(N+2, none)`. Bob can now claim the full multi-cycle backlog despite having staked for only a fraction of the period the sBTC accrued in, while Alice — staked the whole time it accrued — receives nothing.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2158-2167)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2172-2174)
```text
        (asserts! (> calculation-height last-calc)
            ERR_DISTRIBUTION_ALREADY_COMPUTED
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2192-2192)
```text
                (cycle-staked-ustx (get-total-shares-staked-for-cycle stx-cycle none))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2196-2221)
```text
                (no-stx-stakers (is-eq cycle-staked-ustx u0))
                (accrued-rewards-per-ustx (if no-stx-stakers
                    u0
                    (/ (* stx-staker-rewards PRECISION) cycle-staked-ustx)
                ))
                (cumulative-rewards-per-ustx (+ current-rewards-per-ustx accrued-rewards-per-ustx))
                ;; When no STX is staked, fold the staker cut into the reserve, otherwise zero.
                (unallocated-staker-cut (if no-stx-stakers
                    stx-staker-rewards
                    u0
                ))
                (reserve-deposit (+ reserve-cut unallocated-staker-cut))
                (new-reserve-balance (+ cur-reserve reserve-deposit))
            )
            (var-set reserve-balance new-reserve-balance)
            (var-set last-reward-compute-height calculation-height)
            (var-set last-accounted-rewards-only
                (+ prev-accounted-rewards
                    (- gross-accrued-rewards reserve-deposit)
                ))
            (map-set rewards-per-token-for-cycle {
                reward-cycle: stx-cycle,
                bond-index: none,
            }
                cumulative-rewards-per-ustx
            )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2576-2609)
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
        (map-set staker-rewards-per-token-settled-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
            signer: signer,
            staker: staker,
        }
            rewards-per-token
        )
        {
```

**File:** pox-locking/src/pox_5.rs (L205-231)
```rust
pub fn pox_unstake_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
) -> Result<(), LockingError> {
    if unlock_burn_height == 0 {
        return Err(LockingError::PoxInvalidUnlockHeight);
    }

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxUnstakeNotLocked);
    }

    snapshot.update_unlock_v5(unlock_burn_height)?;

    debug!(
        "PoX v5 unstake scheduled";
        "pox_locked_ustx" => snapshot.balance().amount_locked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(())
}
```
