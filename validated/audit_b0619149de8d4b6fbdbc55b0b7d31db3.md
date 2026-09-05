### Title
Reentrant `signer-manager` callback in `register-for-bond` lets a staker corrupt bond accounting and double-count staked shares - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond` in `pox-5.clar` snapshots critical accounting values (`existing-membership`, `old-sbtc`, `current-total-staked`) at the top of the function, then — before writing any of that state — invokes `signer-manager-validate-stake` against a **staker-supplied, untrusted `<signer-manager-trait>` contract**. This is the exact structural pattern flagged in the external report: state is decided based on a pre-callback snapshot, an external/untrusted callback is invoked, and only afterward are the final map writes made using the stale snapshot. A malicious `signer-manager` contract can use its `validate-stake!` callback to re-enter `register-for-bond` and change the very state (`protocol-bond-memberships`, sBTC custody, `protocol-bonds-total-staked`, per-cycle share maps) that the outer call will later overwrite from stale values.

### Finding Description
In `register-for-bond` [1](#0-0) , the `let` binds `existing-membership`, `old-sbtc`, and `current-total-staked` up front. Execution then reaches:

```
(try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1
    amount-ustx sats-total true signer-calldata
))
``` [2](#0-1) 

`signer-manager` is a `<signer-manager-trait>` parameter chosen by the caller, dispatched via `contract-call?` to the caller's own contract implementing `validate-stake!`, as shown in the reference implementation, which itself documents that this is a "pox-5 callback" [3](#0-2) .

Only *after* this untrusted callback does `register-for-bond` perform the overlap check, `verify-bond-rollover-window`, `roll-sbtc` (custody transfer), and the map writes for `protocol-bond-memberships` and `protocol-bonds-total-staked`, using the pre-callback `current-total-staked`/`old-sbtc`/`existing-membership` values:

```
(try! (roll-sbtc tx-sender old-sbtc new-sbtc))
(map-set protocol-bond-memberships tx-sender {...})
(map-set protocol-bonds-total-staked bond-index (+ current-total-staked sats-total))
(try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle BOND_LENGTH_CYCLES sats-total))
(try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle BOND_LENGTH_CYCLES amount-ustx false))
``` [4](#0-3) 

Because `tx-sender` is unchanged across nested `contract-call?`s, a staker can deploy a malicious `signer-manager` contract whose `validate-stake!` re-enters `register-for-bond` (or `stake`/`update-bond-registration`) for the same `tx-sender`/bond/cycle while the outer call's writes haven't happened yet. The reentrant call sees `existing-membership = none`, `old-sbtc = 0`, and the pre-outer `current-total-staked`, so it passes all guards, calls `roll-sbtc` to pull sBTC into custody, and writes its own membership/total/per-cycle shares. When the outer call resumes, it overwrites `protocol-bond-memberships` with its own record, calls `roll-sbtc` a second time using the stale `old-sbtc = 0` (double custody pull), and overwrites `protocol-bonds-total-staked` using the stale `current-total-staked`, discarding the nested call's contribution to the total while the per-cycle share maps (`add-staker-to-bond-cycles`/`add-staker-to-signer-cycles`, which are additive, not idempotent) retain both calls' additions.

This breaks the invariant that `protocol-bonds-total-staked[bond-index]` and the per-cycle share sums equal the actual sBTC custodied and STX locked for that bond, exactly mirroring the vault `nominals`-vs-actual-balance invariant broken in the external report by a mid-function callback.

### Impact Explanation
The corrupted totals feed directly into reward-per-share math (`get-total-shares-staked-for-cycle`) used by `calculate-rewards`/`get-earned`, so a staker can inflate their recorded share of a cycle's rewards relative to the true total, i.e. double-counting a reward commitment, and/or cause the recorded `protocol-bonds-total-staked` to diverge permanently from actual custodied sBTC (temporary/permanent freezing when later withdrawal/rollover math relies on this total). This qualifies as Critical (double-counting a reward / unbacked share of locked value) or at minimum High (signing/reward weight exceeding locked value, temporary freezing of custodied sBTC).

### Likelihood Explanation
The attacker fully controls the `signer-manager` argument to `register-for-bond` (any contract implementing `signer-manager-trait` can be supplied) and needs no privileged role — the trait exists specifically to let arbitrary pool/signer contracts hook into staking. No signer, bond-admin, or miner cooperation is required; a single malicious contract deployment plus one `register-for-bond` transaction is sufficient to trigger the reentrant path.

### Recommendation
Re-order `register-for-bond` (and any other bond/stake function that calls `signer-manager-validate-stake` before finalizing state) so the untrusted trait callback occurs strictly after all state relevant to the transaction (`protocol-bond-memberships`, `protocol-bonds-total-staked`, per-cycle share maps, `roll-sbtc`) has been committed, or add a re-entrancy guard (e.g., a `bool` sentinel checked/set before the callback and cleared at the end) so any re-entrant call into bond/stake-mutating entry points fails while the outer call is still in flight. Additionally, re-read `existing-membership`/`old-sbtc`/`current-total-staked` immediately before use rather than relying on values captured before the external call, or explicitly assert they are unchanged post-callback (mirroring the recommended `totalSupply` check in the referenced fix).

### Proof of Concept
1. Deploy a malicious contract implementing `signer-manager-trait` whose `validate-stake!` function, upon being invoked by pox-5 (i.e., `contract-caller == pox-5`), issues `(contract-call? 'SP....pox-5 register-for-bond bond-index ...)` again for the same `tx-sender`, `bond-index`, and reward cycle, using the same or a related `signer-manager`.
2. As the attacker (tx-sender), call `register-for-bond` with `signer-manager` set to this malicious contract, `bond-index` pointing at an open bond, and valid `sats-total`/`amount-ustx`.
3. Inside `signer-manager-validate-stake`'s invocation of `validate-stake!`, the malicious contract re-enters `register-for-bond` before the outer call has written `protocol-bond-memberships`/`protocol-bonds-total-staked`; the nested call succeeds (guards see stale "no membership" state), custodying sBTC and writing per-cycle shares once.
4. The outer call resumes and re-executes `roll-sbtc`, `map-set protocol-bond-memberships`, and `map-set protocol-bonds-total-staked` using its pre-callback snapshots, pulling a second batch of sBTC and clobbering the total-staked figure while per-cycle share maps retain both contributions.
5. Query `get-total-shares-staked-for-cycle`/`get-earned` for the affected cycle and compare against the actual sBTC balance custodied by pox-5 to observe the mismatch (shares/rewards inflated relative to `protocol-bonds-total-staked`, or custody/total accounting permanently diverged).

Note: the exact numeric outcome depends on the internal bodies of `roll-sbtc`, `add-staker-to-bond-cycles`, and `bond-overlaps-new-position?`, which were not fully retrievable from the indexed context; a Devin session with full repository access should implement the above PoC against `contrib/core-contract-tests` to confirm the precise divergence amount before remediation.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-709)
```text
    (let (
            (signer (contract-of signer-manager))
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
            ;; Any bond the staker is currently a member of. Some value here
            ;; means this is a roll-over from an ending bond into a later one.
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
            ;; sBTC currently custodied for the staker's existing bond (0 if
            ;; they have none, or if the existing bond is an L1 lock).
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
            ;; Any STX-only stake the staker has. Present means this
            ;; `register-for-bond` is a roll-over from an ending stx-only
            ;; stake into a bond.
            (existing-stake (map-get? staker-info tx-sender))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (allowance (unwrap!
                (map-get? protocol-bond-allowances {
                    staker: tx-sender,
                    bond-index: bond-index,
                })
                ERR_NOT_ALLOWLISTED
            ))
            (first-reward-cycle (bond-period-to-reward-cycle bond-index))
            (bond-start-height (bond-period-to-burn-height bond-index))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle BOND_LENGTH_CYCLES))
            (current-total-staked (get-total-shares-staked-for-cycle first-reward-cycle
                (some bond-index)
            ))
            (stx-balance (stx-account tx-sender))
            (total-balance (+ (get locked stx-balance) (get unlocked stx-balance)))
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L753-756)
```text
        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1
            amount-ustx sats-total true signer-calldata
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L772-805)
```text
        ;; Settle rewards before updating state
        (settle-rewards signer first-reward-cycle (some bond-index))
        (settle-staker-rewards signer first-reward-cycle (some bond-index)
            tx-sender
        )

        ;; A rollover from a non-overlapping existing bond may only happen in
        ;; that bond's L1 unlock window, the last 1/2 cycle.
        (try! (verify-bond-rollover-window existing-membership))

        ;; Move the staker's custodied sBTC into this bond, transferring only the
        ;; net difference vs. any bond they're rolling over from.
        (try! (roll-sbtc tx-sender old-sbtc new-sbtc))

        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
            amount-sats: sats-total,
        })
        (map-set protocol-bonds-total-staked bond-index
            (+ current-total-staked sats-total)
        )
        ;; A roll-over from an ending bond ADDS the new bond's shares but does
        ;; NOT tear down the old bond's per-cycle shares/delegation (unlike
        ;; `update-bond-registration`, which removes then re-adds).
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            BOND_LENGTH_CYCLES sats-total
        ))

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            BOND_LENGTH_CYCLES amount-ustx false
        ))
```

**File:** contrib/core-contract-tests/contracts/signer-manager.clar (L111-129)
```text
;; Callback function from a `stake` transaction.
;;
;; If `signer-calldata` is provided, then it must be in the form
;; of `{ version, hashbytes }` as a pox-addr. If provided, the pox-addr
;; is saved for the user, and they'll receive rewards through sBTC withdrawals.
(define-public (validate-stake!
        (staker principal)
        ;; #[allow(unused_binding)]
        (first-index uint)
        ;; #[allow(unused_binding)]
        (num-indexes uint)
        ;; #[allow(unused_binding)]
        (amount-ustx uint)
        ;; #[allow(unused_binding)]
        (amount-sats uint)
        ;; #[allow(unused_binding)]
        (is-bond bool)
        (signer-calldata (optional (buff 500)))
    )
```
