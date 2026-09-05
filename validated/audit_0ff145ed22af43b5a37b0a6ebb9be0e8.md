## Title
Duplicate/reused Bitcoin lockup outpoints can credit `sats-total` across multiple `register-for-bond` calls with no BTC actually locked - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`verify-l1-lockups`/`validate-l1-lockup` in `pox-5.clar` deduplicate Bitcoin lockup outpoints only *within a single call* (`seen-outpoints` starts as `(list)` on every invocation and is never persisted to contract state). There is no global map of already-consumed L1 outpoints. This is analogous to the reported Stream bug class in spirit (a bookkeeping value diverging from the real backing asset), but here it is worse: it directly matches the "sats credited by an L1 proof that were never locked on Bitcoin" / "double-counting a commitment" categories called out in scope.

### Finding Description
`register-for-bond` computes `sats-total` for an L1-collateralized bond via: [1](#0-0) 

which calls `verify-l1-lockups`: [2](#0-1) 

The dedup accumulator `seen-outpoints` is seeded fresh as `(list)` on every call (line 2013) and is discarded once the fold finishes — it is never written to persistent contract state (no `define-map` tracking previously-claimed `(txid, output-index)` pairs anywhere in the file). `validate-l1-lockup` only asserts the outpoint hasn't appeared *earlier in the same list argument*: [3](#0-2) 

Consequently, the exact same Bitcoin transaction output (a single BTC lockup UTXO) that was already used to justify one bond registration's `sats-total` can be resubmitted as proof for a *different* `register-for-bond` call (different `bond-index`, or even the same staker registering a second time after the term ends/rolls, or a colluding staker copying another staker's public on-chain lockup proof for a script whose `staker` field matches). Each successful call credits `sats-total` sats into `protocol-bond-memberships`, `protocol-bonds-total-staked`, and per-cycle share maps used later by `calculate-bond-rewards`/`settle-rewards` to compute sBTC reward payouts — all without any corresponding additional BTC ever being locked.

This breaks the equality the L1 path is supposed to preserve: `sum(sats-total credited across all bond registrations backed by L1 proofs) == sum(actual distinct BTC UTXOs locked)`. Reward payouts (`calculate-bond-rewards`, `claim-rewards`) are apportioned by `amount-sats`/shares, so inflating `sats-total` via a replayed proof directly inflates the attacker's share of real sBTC rewards paid out of the contract's actual sBTC balance — an unbacked/duplicated commitment translating into theft of reward funds.

### Impact Explanation
This matches the in-scope Critical category "sats credited by an L1 proof that were never locked on Bitcoin... double-counting a commitment or reward": an attacker can register for a bond (or multiple bonds/positions) using a lockup proof whose BTC output was already counted, receiving reward shares and allowlist credit disproportionate to BTC actually locked, at the expense of honest bond participants' share of the real sBTC reward pool.

### Likelihood Explanation
Requires only an unprivileged staker with a valid Bitcoin lockup script bound to their principal (i.e., they must be allowlisted for the bond, and the lockup script must encode their own `staker` principal per `construct-lockup-output-script`), and the ability to submit the same header/merkle-proof tuple to `register-for-bond` more than once (e.g., across two allowed bonds, or after the first bond position naturally clears without the outpoint's `sats-total` being marked as spent). Since the contract never records used outpoints persistently, replay across separate transactions is straightforward once the staker qualifies for a second registration window (e.g. rollovers, or new bond periods reusing the same lockup proof rather than a fresh one).

### Recommendation
Persist verified `(txid, output-index)` pairs in a contract-level map (e.g. `used-l1-lockup-outpoints`) and assert non-membership before crediting `sats-total`, marking them used on success — not just deduplicating within the single call's `fold`.

### Proof of Concept
1. Staker registers for `bond-index=0` via `register-for-bond` with `btc-lockup = (err {outputs: [output A], staker-unlock-bytes: ...})`, where output A locks `X` sats. `sats-total = X` is credited; `total-sbtc-staked`/bond shares increase by `X`.
2. After bond 0's term or a rollover eligibility window, the staker (or a second allowlisted principal whose lockup script embeds their principal but who can still reference the same on-chain output, if the check only verifies `is-eq (get script output) expected-script-hash` and `amount`) calls `register-for-bond` for `bond-index=6` (or any other still-open bond) supplying the *same* `output A` bytes/proof again.
3. `validate-l1-lockup`'s only anti-replay check, `seen-outpoints`, is reinitialized to `(list)` for this new call (`verify-l1-lockups`, line 2013), so the check at line 2086-2088 passes trivially.
4. `sats-total = X` is credited a second time into a new bond position, doubling the staker's counted collateral without any new BTC being locked, and proportionally inflating their share of sBTC rewards distributed by `calculate-rewards`/`claim-rewards` out of the contract's real sBTC balance.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-676)
```text
    (let (
            (signer (contract-of signer-manager))
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1984-2019)
```text
(define-private (verify-l1-lockups
        (staker principal)
        (bond-index uint)
        (lockups {
            outputs: (list 10
                {
                    height: uint,
                    tx: (buff 100000),
                    output-index: uint,
                    header: (buff 80),
                    leaf-hashes: (list 14 (buff 32)),
                    tx-count: uint,
                    tx-index: uint,
                    amount: uint,
                    unlock-burn-height: uint,
                }
            ),
            staker-unlock-bytes: (buff 683),
        })
    )
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
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2086-2088)
```text
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
```
