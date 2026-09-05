### Title
Unchecked subtraction in `get-rewards` can cause a permanent, unrecoverable freeze of pox-5 reward accounting - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`get-rewards` computes the reward balance as `current-balance - total-staked-sbtc - cur-reserve` without ever validating that the live sBTC token balance is at least as large as the sum of the two internally-tracked accounting variables it subtracts. This mirrors the PoolTogether `captureAwardBalance` bug class: an internal accounting figure (`total-staked-sbtc` + `reserve-balance`) is trusted to always be less than or equal to the external asset balance it is compared against, with no defensive check.

### Finding Description
`get-rewards` is defined as:
```
(define-read-only (get-rewards)
    (let (
            (cur-reserve (var-get reserve-balance))
            (total-staked-sbtc (get-total-sbtc-staked))
            (current-balance (unwrap-panic (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance current-contract
            )))
        )
        (- current-balance total-staked-sbtc cur-reserve)
    )
)
``` [1](#0-0) 

`get-new-rewards` and `calculate-rewards` both depend transitively on this subtraction: [2](#0-1) 

In Clarity, `(- a b c)` on `uint` aborts the whole transaction on underflow (there is no wrapping). If `total-staked-sbtc + cur-reserve` is ever, even momentarily, greater than the actual sBTC token balance held by the contract, `get-rewards` (and every function that calls it, including `calculate-rewards`, `claim-rewards`, and any read-only integrations) will abort. Because `total-sbtc-staked` and `reserve-balance` are independent Clarity variables maintained purely by internal bookkeeping (`var-set total-sbtc-staked ...` in `unstake-sbtc`, `roll-sbtc`, `stake`/`register-for-bond`, etc.), while the actual balance is the externally verifiable `sbtc-token` balance, any drift between the two — from a rounding difference, an accounting edge case in the bond/staking lifecycle, or a future extension that changes how `total-sbtc-staked` is bumped without a matching real transfer — makes this underflow reachable. Once reachable, the condition is not self-healing: every subsequent call to `calculate-rewards`/`get-rewards` will re-derive the same negative internal value and abort, permanently disabling reward calculation and distribution for all stakers and signers.

I was not able to conclusively trace, within the available index, a concrete on-chain path where an unprivileged staker can force `total-staked-sbtc + cur-reserve > current-balance` (e.g., whether L1-lockup bond registrations increment `total-sbtc-staked` without a corresponding sBTC token transfer into the contract) — the relevant `register-for-bond`/L1-lockup accounting logic in `pox-5.clar` was only partially retrieved before the search budget was exhausted. This is a real limitation of my investigation, not a claim that no path exists.

### Impact Explanation
If reachable, this breaks the equality that staked/reserve sBTC accounting must never exceed the token balance actually held by the contract, and results in permanent freezing of reward distribution (rewards become uncalculatable/unclaimable for every staker and signer, indefinitely, since the state that caused the abort cannot be reduced by any public function). This corresponds to the "permanent freezing of staked STX or sBTC" / "double-counting a commitment" category described in scope, assuming a concrete trigger path exists.

### Likelihood Explanation
Low-to-moderate, and unconfirmed. The current staking/unstaking functions I was able to inspect (`unstake-sbtc`, `roll-sbtc`) keep `total-sbtc-staked` updates paired 1:1 with actual `sbtc-token` transfers, which would normally prevent drift. However, `get-rewards` performs no defensive check regardless, so any future or currently-unverified code path (e.g., L1 lockup accounting, rounding in bond distribution, or a reentrancy edge case) that increments `total-sbtc-staked`/`reserve-balance` without an exactly matching real transfer would immediately and permanently brick this subsystem. The complete absence of a `checked_sub`/`asserts!` guard here, in a contract that otherwise uses `asserts!`/`unwrap!` defensively everywhere else, is itself the anomaly worth flagging regardless of whether I could fully confirm a trigger.

### Recommendation
Add an explicit guard in `get-rewards` before subtracting, e.g.:
```clarity
(asserts! (>= current-balance (+ total-staked-sbtc cur-reserve)) ERR_...)
```
or use saturating subtraction that returns `u0` instead of aborting, matching the PoolTogether fix pattern (checking that the subtrahend does not exceed the accumulated balance before subtracting) so a transient or unexpected accounting drift degrades gracefully (e.g., reports zero new rewards) instead of permanently halting all reward computation for the protocol.

### Proof of Concept
Not reproducible from the available code alone — the analysis identifies the missing-check pattern in `get-rewards` (`stackslib/src/chainstate/stacks/boot/pox-5.clar:2135-2145`) as structurally identical to the referenced `captureAwardBalance` underflow bug, but confirming a concrete unprivileged trigger requires tracing every code path that mutates `total-sbtc-staked` and `reserve-balance` (including L1-lockup bond registration and any future signer-manager interactions) against the corresponding `sbtc-token` transfers, which was not completed within the available investigation budget.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2135-2145)
```text
(define-read-only (get-rewards)
    (let (
            (cur-reserve (var-get reserve-balance))
            (total-staked-sbtc (get-total-sbtc-staked))
            (current-balance (unwrap-panic (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance current-contract
            )))
        )
        (- current-balance total-staked-sbtc cur-reserve)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2147-2166)
```text
;; Returns the total amount of newly received sBTC rewards
;; since the last rewards computation
(define-read-only (get-new-rewards)
    (let (
            (last-accounted-rewards (var-get last-accounted-rewards-only))
            (rewards-balance (get-rewards))
        )
        (- rewards-balance last-accounted-rewards)
    )
)

(define-public (calculate-rewards (bond-periods (list 6 uint)))
    (let (
            (last-calc (var-get last-reward-compute-height))
            (calculation-height (- (distribution-cycle-to-burn-height (current-distribution-cycle))
                u1
            ))
            (cur-reserve (var-get reserve-balance))
            (gross-accrued-rewards (get-new-rewards))
            (stx-cycle (burn-height-to-reward-cycle calculation-height))
```
