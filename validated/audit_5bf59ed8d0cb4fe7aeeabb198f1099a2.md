Based on my investigation, I found strong structural evidence in pox-5.clar for the same bug class described in the Exactly report, but I was unable to fully verify all call sites within the final iteration budget. I'll report what is confirmed and flag what remains unverified.

### Title
Potential unsettled reward-per-token manipulation if a share-mutating path skips `settle-rewards`/`settle-staker-rewards` in pox-5.clar - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
The Exactly bug class is: a variable that feeds a rate/utilization calculation (`floatingBackupBorrowed`) can be mutated by some code paths without first accruing/settling the dependent global state (`floatingDebt`), letting an attacker manipulate past accrual using current-block information. `pox-5.clar` has a structurally identical dependency: `signer-shares-staked-for-cycle` / `staker-shares-staked-for-cycle` feed the rewards-per-token calculation, and the contract's own doc-comments assert an invariant that `settle-rewards` / `settle-staker-rewards` **MUST** be called before any update to those share maps [1](#0-0) , and the same invariant is stated for staker settlement [2](#0-1) .

### Finding Description
`settle-rewards` computes `earned` from `shares * (rewards-per-token - settled-per-token)` and then snapshots the current `rewards-per-token` against the signer's settled value [3](#0-2) . This is exactly the "accrue-before-mutate" pattern the Exactly report says was missing for `floatingBackupBorrowed`: if a share-changing function updates `signer-shares-staked-for-cycle`/`staker-shares-staked-for-cycle` (or the underlying `*-to-cycles` map helpers) **without** first calling `settle-rewards`/`settle-staker-rewards`, the reward-per-token snapshot would be computed against a share value that no longer matches the actual shares held during the un-settled interval — permanently mis-crediting or double-crediting rewards, the same equality violation described in the M-5 report (unrealized "debt"/reward manipulation via stale utilization/share state).

`update-bond-registration` demonstrates the correct pattern: it calls `settle-rewards` for both old and new signer and `settle-staker-rewards` for both, explicitly *before* calling `remove-staker-from-cycles`, `add-staker-to-signer-cycles`, `remove-staker-from-bond-cycles`, and `add-staker-to-bond-cycles` [4](#0-3) . The CHANGELOG for this repo also documents a *related*, already-fixed regression of exactly this shape — a signer switch that let the new signer start earning rewards despite signing power not yet reflecting reality, and a fix preventing double-collection of already-distributed bond rewards on a new signer after signer changes [5](#0-4) [6](#0-5) . This shows the maintainers are aware of and actively patching this exact bug class in pox-5, meaning other share-mutating entry points (`stake`, `register-for-bond`, `unstake`, `unstake-sbtc`, rollover paths, etc.) are the natural places where a missed `settle-rewards`/`settle-staker-rewards` call would reproduce the M-5 pattern.

### Impact Explanation
If confirmed, this would fall under the "High" impact tier: signing weight or reward accounting exceeding what was actually locked/staked, or duplicate/lost reward crediting for stakers and signers, without needing any privileged role — any staker calling a public entry point (e.g. `stake`, `unstake`, `register-for-bond`) could trigger it.

### Likelihood Explanation
**Uncertain — not confirmed.** I was only able to verify that (a) the invariant is explicitly documented as required in two places, (b) one function (`update-bond-registration`) correctly honors it, and (c) the CHANGELOG shows a related bug of this class was already fixed once. I ran out of tool-call budget before I could grep every other public function that touches `signer-shares-staked-for-cycle`/`staker-shares-staked-for-cycle` (or the `add-staker-to-cycles`/`remove-staker-from-cycles`/`add-staker-to-bond-cycles`/`remove-staker-from-bond-cycles`/`add-staker-to-signer-cycles` helpers) to check whether every call site precedes its mutation with the required `settle-rewards`/`settle-staker-rewards` calls. Given that the maintainers have already had to fix one instance of this exact class, it is plausible but **not proven** that another path still lacks the settlement call.

### Recommendation
A background agent should grep every call site of `settle-rewards` and `settle-staker-rewards` in `stackslib/src/chainstate/stacks/boot/pox-5.clar`, cross-reference against every call site of `signer-shares-staked-for-cycle`/`staker-shares-staked-for-cycle` mutation helpers (`add-staker-to-cycles`, `remove-staker-from-cycles`, `add-staker-to-signer-cycles`, `add-staker-to-bond-cycles`, `remove-staker-from-bond-cycles`, and any `map-set` on those maps), and confirm that every public entry point (`stake`, `unstake`, `unstake-sbtc`, `register-for-bond`, rollover functions, `update-bond-registration`) settles rewards for all affected signers/stakers *before* mutating shares — matching the pattern already used correctly in `update-bond-registration` [4](#0-3) .

### Proof of Concept
Not available — a concrete PoC requires confirming a specific missing call site, which I could not verify within the tool-call budget available for this analysis.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L895-919)
```text
        ;; Settle rewards before mutating related state
        (settle-rewards current-signer current-cycle (some bond-index))
        (settle-rewards signer current-cycle (some bond-index))
        (settle-staker-rewards current-signer current-cycle (some bond-index)
            tx-sender
        )
        (settle-staker-rewards signer current-cycle (some bond-index) tx-sender)

        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender first-reward-cycle num-cycles false))

        ;; Re-add to existing cycles with the new signer
        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            num-cycles (get amount-ustx current-membership) false
        ))

        ;; Remove the sBTC shares from the current signer
        (try! (remove-staker-from-bond-cycles tx-sender current-signer bond-index
            first-reward-cycle num-cycles amount-sats
        ))

        ;; Add the sBTC shares to the current signer
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            num-cycles amount-sats
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2525-2573)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2576-2580)
```text
;; Update all earned-but-unclaimed rewards for a staker, and update the snapshot
;; (staker-rewards-per-token-settled-for-cycle) for the staker.
;;
;; This MUST be called before any update to `staker-shares-staked-for-cycle`,
;; because changes to that state will effect rewards calculations.
```

**File:** CHANGELOG.md (L79-79)
```markdown
* pox-5: `announce-l1-early-exit` is now callable by the staker themselves, not the bond's early-unlock admin. The `early-unlock-admin` field is removed from `protocol-bonds` and from the `setup-bond` parameter list, since no on-chain code path consumes it anymore. Re-announcing for the same bond returns the new `ERR_L1_EARLY_EXIT_ALREADY_ANNOUNCED`. The new read-only `has-announced-l1-early-exit` exposes per-staker announcement state for off-chain consumers and gates the re-entry assert on-chain.
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L3948-3956)
```typescript
/**
 * Regression: changing signer for an active bond must not let the staker
 * double-collect already-distributed bond rewards on the new signer. Before
 * the fix, `update-bond-registration` did not settle the staker's per-token
 * snapshot for the new signer, so the new signer's `rpt-paid` defaulted to 0
 * while shares were copied over. The staker's earned-on-new-signer would
 * then equal `shares * (rpt-current - 0) / PRECISION` — a duplicate of the
 * rewards already accrued on the old signer.
 */
```
