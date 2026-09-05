### Title
Unvalidated direct sBTC balance read in `get-rewards` lets donated tokens inflate `rewards-per-token-for-cycle` accumulators, permanently freezing withdraw/claim paths - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`get-rewards`/`get-new-rewards` compute "earned" sBTC rewards purely from the live sBTC-token balance of the pox-5 contract rather than from a tracked, validated inflow of rewards. Any account can `transfer` sBTC directly to the pox-5 contract address (a donation, exactly the pattern in the referenced report) and that donation is indistinguishable from genuine bond/signer rewards. It is folded into `gross-accrued-rewards` in `calculate-rewards` and multiplied into the `rewards-per-token-for-cycle` accumulators used by `compute-earned-rewards`. Because these accumulators are monotonically increasing native Clarity `uint`s (128-bit, abort-on-overflow, analogous to the Solidity `assertFitsInUint151` revert in the original report), a donation-inflated numerator combined with a small `total-sats`/`cycle-staked-ustx` denominator can push the stored accumulator toward the point where a later `shares * (rpt-current - rpt-paid)` multiplication in `compute-earned-rewards` aborts, permanently freezing `claim-rewards`/`unstake-sats-from-bond-cycle` for that reward-cycle/bond-index.

### Finding Description
`get-rewards` is defined as: [1](#0-0) 

and `get-new-rewards` simply diffs this live balance against `last-accounted-rewards-only`: [2](#0-1) 

`calculate-rewards` treats this diff as the pool of "gross-accrued-rewards" to distribute to bonds and STX stakers, computing `accrued-rewards-per-ustx = (gross-accrued-rewards-derived stx-staker-rewards * PRECISION) / cycle-staked-ustx` and folding it into `cumulative-rewards-per-ustx`, which is stored via `map-set rewards-per-token-for-cycle`: [3](#0-2) 

The per-bond path does the analogous thing in `calculate-bond-rewards`, computing `accrued-rewards-per-sat = (earned * PRECISION) / total-sats` and adding it to the existing `rewards-per-token-for-cycle` entry: [4](#0-3) 

Both accumulators feed `compute-earned-rewards`, which multiplies staker/signer `shares` by the accumulator delta: [5](#0-4) 

This function is reached from `get-earned`/`get-earned-staker-rewards`, and from `settle-rewards`/`settle-staker-rewards`, which are invoked both by the claim path (`claim-rewards`, `update-claimable-rewards`) and by the unstake/withdraw path (`unstake-sats-from-bond-cycle`): [6](#0-5) 

None of `get-rewards`, `calculate-rewards`, or `calculate-bond-rewards` validate that the sBTC balance increase actually corresponds to a legitimate, tracked signer/bond payment — any principal can call `sbtc-token transfer` directly to the pox-5 contract to inflate `current-balance`, and the very next `calculate-rewards` call will count it as "earned" yield with no cap tied to `total-sats`/`cycle-staked-ustx`. Because `rewards-per-token-for-cycle` values only ever increase (each `calculate-rewards` call adds to the existing entry) and Clarity `uint` arithmetic aborts on overflow rather than wrapping, a sequence of donations against a cycle/bond with a small staked denominator can drive the accumulator toward the point where the later multiplication in `compute-earned-rewards` (`shares * (rpt-current - rpt-paid)`) aborts for every caller referencing that reward-cycle/bond-index — exactly the failure mode described in the report (`assertFitsInUint151`/`UintOverflowed` in the Solidity analog), except here it blocks `claim-rewards` and, more importantly, the withdraw path `unstake-sats-from-bond-cycle`.

### Impact Explanation
This breaks the equality that sBTC rewards credited to a reward-cycle/bond must correspond to rewards actually earned/authorized for that cycle — a donation makes `rewards paid > rewards earned` (double counting/uncontrolled inflation of the reward pool), and if the resulting accumulator later overflows, it permanently freezes the ability of legitimate stakers/signers to `claim-rewards` or unstake (`unstake-sats-from-bond-cycle`) for the affected reward-cycle/bond-index — a permanent freezing of staked sBTC/STX and unclaimed rewards. Both "sBTC rewards paid that were not earned or counted twice" and "permanent freezing of staked STX or sBTC" are in the allowed Critical/High impact set.

### Likelihood Explanation
Sending sBTC directly to the pox-5 contract requires no special privilege — any unprivileged account holding sBTC can call the standard `sbtc-token transfer` function. Triggering `calculate-rewards`/`calculate-bond-rewards` afterward is a normal, unprivileged public call. The main uncertainty is whether an attacker can accumulate a large enough donated total, relative to a sufficiently small `total-sats`/`cycle-staked-ustx` denominator, to actually drive the u128 accumulator to the overflow threshold within a realistic number of donation/`calculate-rewards` cycles (sBTC's real supply is bounded by locked BTC, unlike the mock ERC20 used in the original report's PoC, so a single-shot overflow is less trivial). This bounds the likelihood versus the original report's arbitrary `mint`, but the underlying reachable path — direct, unvalidated balance reads driving a strictly increasing on-chain accumulator — is present and repeatable across many reward cycles.

### Recommendation
Do not derive `get-rewards`/`get-new-rewards` from the live sBTC balance of the contract. Instead, require reward inflows to go through an explicit, authenticated "deposit rewards" entry point that records the amount in a dedicated tracked variable, and compute `gross-accrued-rewards` from that tracked variable rather than `contract-call? ... get-balance current-contract`. Additionally, bound `rewards-per-token-for-cycle` updates (e.g., via an explicit max-per-cycle cap or `try!`-guarded checked arithmetic with a defined ceiling) so that even a large tracked inflow cannot push the accumulator toward the u128 abort boundary.

### Proof of Concept
1. Attacker (or any account) calls `sbtc-token transfer` sending sBTC directly to the pox-5 contract's principal — this is not intercepted by any pox-5 function and does not require any bond/staking action.
2. Attacker (or anyone) calls `calculate-rewards` — `get-new-rewards` reads the inflated `current-balance` via `contract-call? ... get-balance current-contract` [7](#0-6)  and folds the donated amount into `gross-accrued-rewards`, which is distributed through `calculate-bond-rewards`/`accrued-rewards-per-ustx` into `rewards-per-token-for-cycle` [8](#0-7) .
3. Repeating steps 1–2 against reward-cycles/bonds with a small `total-sats`/`cycle-staked-ustx` denominator monotonically grows the stored `rewards-per-token-for-cycle` entry (no cap or reset), since it is always `(+ current-rewards-per-token accrued-rewards-per-sat)` [9](#0-8) .
4. Once the accumulator is large enough, any later call into `compute-earned-rewards` (via `claim-rewards`, `update-claimable-rewards`, or the withdraw path `unstake-sats-from-bond-cycle` → `settle-rewards`/`settle-staker-rewards` → `get-earned`) performs `shares * (rpt-current - rpt-paid)` [10](#0-9) , which aborts on native `uint` overflow, blocking legitimate stakers/signers from claiming rewards or unstaking their sats for that reward-cycle/bond-index.

**Uncertainty note:** I was not able to fully verify the exact value of `PRECISION`, the practical bound on sBTC supply relative to the smallest realistic `total-sats` denominator, or run an actual PoC transaction sequence, so I cannot confirm the precise number of donation/`calculate-rewards` iterations required to trigger the overflow abort in practice. The reachable code path and the absence of any validation tying `get-rewards` to actually-earned/authorized inflows are confirmed directly from the cited source.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1368-1410)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2134-2156)
```text
;; Returns the total balance of rewards received by the contract
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2158-2221)
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

        ;; verify that we are able to compute here
        (asserts! (> calculation-height last-calc)
            ERR_DISTRIBUTION_ALREADY_COMPUTED
        )

        ;; Verify that all active bonds are included
        (try! (assert-all-active-bonds-included bond-periods calculation-height))

        (let (
                (bond-distributions (try! (fold calculate-bond-rewards bond-periods
                    (ok {
                        last-bond-stx-value-ratio: none,
                        available-rewards: gross-accrued-rewards,
                        last-bond-index: none,
                        calculation-height: calculation-height,
                        reward-cycle: stx-cycle,
                    })
                )))
                (remaining-rewards (get available-rewards bond-distributions))
                (reserve-cut (/ (* remaining-rewards RESERVE_RATIO) u10000))
                (stx-staker-rewards (- remaining-rewards reserve-cut))
                (cycle-staked-ustx (get-total-shares-staked-for-cycle stx-cycle none))
                (current-rewards-per-ustx (get-rewards-per-token-for-cycle stx-cycle none))
                (prev-accounted-rewards (var-get last-accounted-rewards-only))
                ;; If no STX is staked this cycle, the staker cut will be applied to the reserve.
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2262-2309)
```text
            (total-sats (get-total-shares-staked-for-cycle reward-cycle (some bond-index)))
            (available-rewards (get available-rewards accumulator))
            ;; How much sBTC the bond is supposed to earn per calculation,
            ;; which is (totalSats * apy) / 50
            (target-yield (/ (/ (* total-sats (get target-rate bond)) u10000) u50))
            ;; If there is enough to cover the target yield, use that. Otherwise,
            ;; this bond gets the remaining rewards.
            (earned (if (>= available-rewards target-yield)
                target-yield
                available-rewards
            ))
            (stx-value-ratio (get stx-value-ratio bond))
            (current-rewards-per-token (get-rewards-per-token-for-cycle reward-cycle (some bond-index)))
            ;; Prevent divide-by-zero
            (accrued-rewards-per-sat (if (is-eq total-sats u0)
                u0
                (/ (* earned PRECISION) total-sats)
            ))
            (calculation-height (get calculation-height accumulator))
            (bond-start-height (bond-period-to-burn-height bond-index))
            (bond-end-height (bond-period-to-burn-height (+ bond-index u6)))
        )
        ;; Verify that we're paying out bonds in the right order
        (match (get last-bond-stx-value-ratio accumulator)
            last-ratio
            (asserts!
                ;; In a tie-breaker, we still want deterministic results.
                ;; Thus, enforce that the earlier bond period comes first
                (if (is-eq stx-value-ratio last-ratio)
                    ;; Note that < prevents the same bond period from
                    ;; being included twice
                    (> bond-index
                        (unwrap-panic (get last-bond-index accumulator))
                    )
                    (<= stx-value-ratio last-ratio)
                )
                ERR_INVALID_BOND_PERIOD_ORDERING
            )
            ;; When `none`, this is the first bond we're processing
            true
        )

        (map-set rewards-per-token-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some bond-index),
        }
            (+ current-rewards-per-token accrued-rewards-per-sat)
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2375-2385)
```text
;; Pure math formula for computing rewards earned since the last snapshot
;;
;; `earned = (shares * (rpt - rptPaid)) / PRECISION + pending`
(define-read-only (compute-earned-rewards
        (shares uint)
        (rpt-current uint)
        (rpt-paid uint)
        (pending uint)
    )
    (+ pending (/ (* shares (- rpt-current rpt-paid)) PRECISION))
)
```
