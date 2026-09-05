### Title
sBTC balance-based reward accounting lets anyone inflate `get-rewards()` via a direct transfer to pox-5 - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`pox-5.clar`'s `get-rewards` computes the distributable reward pool as the contract's *actual* sBTC token balance minus tracked staked/reserve amounts, exactly the balance-diffing pattern flagged in the external Umbrella report (`_coverDeficit()` using `balanceOf(address(this))` instead of the delta actually received). Because `get-rewards`/`get-new-rewards` read the live `sbtc-token` balance rather than an internally accounted "received amount," any unprivileged account can push the accounting off from what governance/protocol logic intends by transferring sBTC directly to the contract.

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

and `get-new-rewards` derives the newly-arrived reward delta from it:
```
(define-read-only (get-new-rewards)
    (let (
            (last-accounted-rewards (var-get last-accounted-rewards-only))
            (rewards-balance (get-rewards))
        )
        (- rewards-balance last-accounted-rewards)
    )
)
``` [2](#0-1) 

Both feed `calculate-rewards`, which distributes `gross-accrued-rewards` (derived from `get-new-rewards`) across bonds and STX-only stakers, and updates `reserve-balance` and `last-accounted-rewards-only` from it. [3](#0-2) 

This mirrors the exact bug class in the external report: instead of tracking "amount actually deposited by the intended caller" via an internal counter, the contract infers it from `balanceOf(this)` (here, `get-balance current-contract`), which any account can inflate by directly transferring sBTC to the pox-5 contract principal — no privileged role or specific caller is required, since `sbtc-token transfer` is a standard SIP-010 call anyone can invoke with the contract as recipient.

### Impact Explanation
An unprivileged account transferring sBTC directly to the pox-5 contract inflates `current-balance`, which flows straight into `get-rewards`/`get-new-rewards`, and hence into `gross-accrued-rewards` consumed by `calculate-rewards` for that distribution period. This lets an attacker (or any well-meaning but uninformed party) directly and permanently alter the reward pool that gets divided among bond participants and stakers, without going through the deposit/reward-accrual path the protocol otherwise gates via `stake-sbtc`/claim flows. This breaks the equality between "sBTC rewards paid" and "sBTC actually earned/deposited as rewards through the intended flow," which the report's rule set calls out explicitly as in-scope (sBTC rewards paid that were never earned/counted through the correct path). It does not, by itself, produce an underflow/panic in this Clarity contract (Clarity's checked subtraction would abort rather than wrap), so the direct "DoS via underflow" impact from the Solidity report doesn't translate 1:1 here — but the value-accounting mismatch (unbacked reward distribution based on external, unauthenticated transfers) does replicate the report's core "balance vs. delta" root cause.

### Likelihood Explanation
Triggering the underlying primitive only requires a standard SIP-010 `transfer` call sending sBTC to the pox-5 contract's principal — no special permissions, timing, or coordination with governance actions is needed, unlike the original DoS-via-frontrunning scenario. This makes the balance-inflation input trivially reachable, though the actual downstream *impact* depends on how `calculate-rewards`/`assert-all-active-bonds-included` bounds and distributes the resulting number across bonds/stakers, which limits (but does not eliminate) how an attacker could disproportionately benefit.

### Recommendation
Replace the `get-balance`-diff approach in `get-rewards`/`get-new-rewards` with an internally tracked "cumulative rewards received" counter that is only incremented through the deposit/reward-crediting code path (e.g., incremented explicitly wherever sBTC is intentionally sent to the contract as a reward), rather than inferred from the live token balance, so that unsolicited direct transfers cannot be counted as rewards or affect `reserve-balance`/`last-accounted-rewards-only` bookkeeping.

### Proof of Concept
1. Any account calls `sbtc-token transfer` sending an arbitrary amount of sBTC to the `pox-5` contract principal (`current-contract` as recipient), which does not go through `stake-sbtc` or any pox-5 entrypoint.
2. Later, when `calculate-rewards` runs, `get-rewards`/`get-new-rewards` reads the contract's sBTC balance via `get-balance`, which now includes the attacker's unsolicited transfer, at: [4](#0-3) 
3. `calculate-rewards` treats this inflated delta as `gross-accrued-rewards` and distributes it to bonds/stakers via `calculate-bond-rewards`/reserve accounting. [5](#0-4) 

Note: I was unable to fully trace the `stake-sbtc`/`unstake-sbtc` and `register-for-bond` entrypoints in this session (tool access ran out before completing that read), so I cannot confirm whether those functions themselves independently update `total-staked-sbtc` before or after the sBTC transfer in a way that could compound this issue (e.g., a race where a legitimate stake deposit is misattributed as reward before state update). This would need further verification via a Devin session with direct file access if deeper confirmation is required.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2147-2156)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2158-2190)
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
```
