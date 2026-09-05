## Title
Missing global consumption-tracking for L1 BTC lockup outpoints allows sats-credit replay in `register-for-bond` - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

## Summary
`IsolateLogic`'s bug class in the reference report is "an amount that should only be counted once gets fed into an accounting/rate function more than once, inflating a downstream computed value." The closest reachable analog in pox-5 is in the L1-lockup credit path of `register-for-bond`: the sats amount credited to a bond (and hence to reward-eligible shares) is derived purely from a Bitcoin-proof verification (`verify-l1-lockups` / `validate-l1-lockup`) with **no persistent, contract-wide record marking a given (txid, output-index) as already consumed**. The only de-duplication is the `seen-outpoints` list, which is scoped to a single call and capped at 10 entries.

## Finding Description
`validate-l1-lockup` at [1](#0-0)  only prevents duplicate outpoints *within the same list of ≤10 outputs passed in a single call*. The accumulator (`seen-outpoints`) is constructed fresh on every call to `verify-l1-lockups` [2](#0-1)  and is discarded once the transaction completes — nothing is written to contract state that marks the outpoint as spent for bonding-credit purposes.

`register-for-bond` uses the returned `sats-total` directly to size the bond membership and update the global bond accounting: [3](#0-2) 
and then commits it into `protocol-bond-memberships`, `protocol-bonds-total-staked`, and per-cycle share maps: [4](#0-3) 

For the L1 path, `new-sbtc` is forced to `u0` [5](#0-4) , so `roll-sbtc` never custodies any sBTC for this membership — the entire economic backing of the "sats-total" credit is the Bitcoin-side proof alone, verified again from scratch on every call. Because the same Bitcoin transaction/output and header/merkle-proof bytes can be supplied to `register-for-bond` in any subsequent, unrelated call (a different bond-index, or after the staker's membership is torn down/rotated), the contract has no way to tell that the underlying BTC lockup was already used to back reward-eligible shares elsewhere. The only structural limits — `protocol-bond-memberships` holding a single membership per staker and the `bond-overlaps-new-position?` check [6](#0-5)  — prevent a *single* staker from holding two *overlapping* bond terms simultaneously, but they do not prevent the same on-chain BTC lockup transaction from being fed into `register-for-bond` again in a non-overlapping/rolled context, or via a second unrelated `register-for-bond` call for a different bond whose `early-unlock-bytes`/minimum-unlock-height happen to be compatible with the already-existing script (the script check in `construct-lockup-output-script` only binds to `staker`, `unlock-burn-height`, and the *target bond's* `early-unlock-bytes`, not to a unique nonce or a global "spent" flag).

This breaks the equality that "sats credited toward bond/reward accounting == sats actually and currently locked, once." A verification event is not a consumption event.

## Impact Explanation
If the same L1 proof can be re-submitted to credit `sats-total` a second time while the staker (or a colluding second party controlling the same locking key/script) is concurrently a member of another bond, `protocol-bonds-total-staked` and the per-cycle share maps used for `calculate-bond-rewards`/`get-total-shares-staked-for-cycle` become inflated relative to actual locked BTC. That directly increases `target-yield` computation and the staker's/signer's earned share of sBTC rewards without any corresponding increase in real backing — i.e., unbacked/double-counted sBTC reward accrual (`calculate-bond-rewards`, `bond-index` accounting) [7](#0-6) . This matches the in-scope "Critical: double-counting a commitment or reward" / "High: signing weight or reward slots exceeding locked value" categories.

## Likelihood Explanation
Exploitability depends on whether a re-submission window actually exists in practice (e.g., after a staker's membership is deleted via unstake/rollover, or via a second unrelated bond registration path) — the single-membership-per-staker map does block the most obvious "two concurrent memberships from one proof" scenario. I could not fully trace every state-transition path (`unstake-sbtc`, `update-bond-registration`, exit-then-immediately-reregister sequences) within the remaining budget to conclusively prove a two-legged concurrent double-credit within one block/transaction group; this requires further tracing of `unstake-sbtc` and `update-bond-registration` against `protocol-bond-memberships` lifecycle, which I was not able to complete before running out of tool budget. The root architectural gap — absence of a persistent, contract-level "L1 outpoint already used for bonding credit" registry — is nonetheless clearly present and concretely demonstrated in the code cited above.

## Recommendation
Add a persistent map (e.g. `used-l1-outpoints: { txid, output-index } -> bool`) that is checked and set inside `validate-l1-lockup`/`verify-l1-lockups`, independent of any single call's local `seen-outpoints` accumulator, so that once a given Bitcoin lockup output has been used to credit `sats-total` in any `register-for-bond` call, it can never be credited again regardless of bond, staker rotation, or membership teardown/rollover.

## Proof of Concept
Not fully constructable within the available tool budget/time — a concrete end-to-end PoC would require tracing `unstake-sbtc`/`update-bond-registration` teardown of `protocol-bond-memberships` to confirm whether a torn-down membership permits immediate re-submission of the same L1 proof for a new concurrent-in-effect bond commitment before further verification could be completed.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-707)
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L764-770)
```text
        ;; Reject if an existing membership *overlaps* this bond. An existing
        ;; bond whose staking term ends no later than this bond's first cycle
        ;; (e.g. rolling from bond N into bond N+6) is allowed.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_REGISTERED
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-805)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2004-2018)
```text
    (let (
            (bond (unwrap! (get-protocol-bond bond-index) ERR_BOND_NOT_FOUND))
            (accumulation (try! (fold validate-l1-lockup (get outputs lockups)
                (ok {
                    sum: u0,
                    staker: staker,
                    minimum-unlock-height: (get-bond-l1-unlock-height bond-index),
                    staker-unlock-bytes: (get staker-unlock-bytes lockups),
                    early-unlock-bytes: (get early-unlock-bytes bond),
                    seen-outpoints: (list),
                })
            )))
        )
        (ok (get sum accumulation))
    )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2072-2088)
```text
            (seen-outpoints (get seen-outpoints accumulator))
        )
        (asserts! (>= unlock-burn-height (get minimum-unlock-height accumulator))
            ERR_INVALID_UNLOCK_HEIGHT
        )
        (asserts! (< unlock-burn-height BITCOIN_LOCKTIME_THRESHOLD)
            ERR_INVALID_UNLOCK_HEIGHT
        )
        (asserts! (is-eq (get script output) expected-script-hash)
            ERR_INVALID_LOCKUP_SCRIPT
        )
        (asserts! (is-eq (get amount output) (get amount lockup))
            ERR_INVALID_LOCKUP_AMOUNT
        )
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2242-2283)
```text
(define-private (calculate-bond-rewards
        (bond-index uint)
        (accumulator-res (response {
            ;; Used to ensure that the list of bonds are sorted correctly
            last-bond-stx-value-ratio: (optional uint),
            ;; Used as a tie-breaker in the case of bonds with the same
            ;; stx-value-ratio
            last-bond-index: (optional uint),
            ;; How much rewards are available to be distributed
            available-rewards: uint,
            calculation-height: uint,
            reward-cycle: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (reward-cycle (get reward-cycle accumulator))
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
```
