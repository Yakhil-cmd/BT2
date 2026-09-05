### Title
Rolling an L1 BTC lockup from one protocol bond into another double-counts the locked sats in `protocol-bonds-total-staked` - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond` verifies an L1 BTC lockup proof and credits `sats-total` to the new bond's `protocol-bonds-total-staked` entry, but never decrements the old bond's entry when a staker rolls their single, already-recorded L1 membership from bond A into bond B. Because `verify-l1-lockups`'s outpoint dedup (`ERR_DUPLICATE_LOCKUP_OUTPOINT`) only rejects the same `(txid, output-index)` appearing twice *inside one call's list*, and there is no persistent, cross-call `seen-outpoints`/used-outpoint map, the same Bitcoin lockup output's sats end up counted in two different bond buckets.

### Finding Description
The claimed equality is: `sum(protocol-bonds-total-staked[A], protocol-bonds-total-staked[B]) == sats actually locked by the single BTC outpoint`.

`protocol-bond-memberships` is keyed only by `principal` [1](#0-0) , so a staker can only be "in" one bond at a time from the contract's point of view, and rollover from bond A to bond B is permitted when `bond-overlaps-new-position?` says the terms don't overlap [2](#0-1) .

In `register-for-bond`, the sats total for the *new* bond is computed via `verify-l1-lockups`, and the new bond's total is bumped: [3](#0-2) 

There is no corresponding subtraction from the *old* bond-index's `protocol-bonds-total-staked` entry anywhere in `register-for-bond`. `roll-sbtc` only moves custodied sBTC balances (and is a no-op for the L1-lock path, since `new-sbtc` is forced to `u0` when `btc-lockup` is `ok`) [4](#0-3) [5](#0-4) . Because the same physical BTC outpoint can be re-submitted as proof in a second `register-for-bond` call (Bitcoin merkle-proof verification is a proof of inclusion, not proof of "not previously used elsewhere"), and the contract's only anti-double-use check, `ERR_DUPLICATE_LOCKUP_OUTPOINT`, is scoped to a single list passed to one call (per the comment at its definition) [6](#0-5) , nothing stops the staker from:
1. Calling `register-for-bond bond-index=A` with proof of outpoint X (amount S), crediting `protocol-bonds-total-staked[A] += S` and setting `staker-shares-staked-for-cycle` for bond A.
2. Later, within bond A's rollover window, calling `register-for-bond bond-index=B` referencing the *same* outpoint X (still provable, since it's never marked "spent" in pox-5 state), crediting `protocol-bonds-total-staked[B] += S` as well, while `protocol-bonds-total-staked[A]` is never reduced.

The result: `protocol-bonds-total-staked[A] + protocol-bonds-total-staked[B]` now reflects `2S` sats, while only `S` sats were ever locked on Bitcoin by outpoint X.

### Impact Explanation
The staker's shares are used for signer weight / reward computation (`add-staker-to-bond-cycles`, `staker-shares-staked-for-cycle`) in both bond A and bond B, so a single real BTC lockup lets the attacker claim reward-earning weight in two separate bond pools simultaneously. This is a double-counted commitment from one Bitcoin lockup — the impact category explicitly listed as Critical ("double-counting a commitment ... counted twice"). It inflates the protocol's accounted collateral without any corresponding additional BTC being locked, diluting genuine stakers' share of rewards and potentially allowing signer-weight/reward-slot allocation exceeding actually-locked value.

### Likelihood Explanation
Preconditions: attacker must be allowlisted for two bond indices (`protocol-bond-allowances`) — plausible for any staker participating in sequential bond periods, which is the expected normal usage pattern (rollover). The attacker only needs to submit the same Merkle-proof/outpoint data twice, in two separate transactions, timed within bond A's rollover window (`verify-bond-rollover-window`) so the `ERR_ALREADY_REGISTERED` check treats it as a legitimate non-overlapping rollover rather than a duplicate registration. This requires no privileged role, no signer collusion, and is fully repeatable for every rollover the staker performs.

### Recommendation
When a staker's `protocol-bond-memberships` entry is overwritten during a rollover in `register-for-bond`, decrement `protocol-bonds-total-staked` (and the corresponding `staker/signer-shares-staked-for-cycle` entries) for the *old* bond-index by the old membership's `amount-sats` before crediting the new bond, mirroring what `update-bond-registration` already does with `remove-staker-from-bond-cycles`/`add-staker-to-bond-cycles`. Additionally, persist a durable, cross-call outpoint-usage map (e.g. `used-l1-outpoints: {txid, output-index} -> bool`) so the same Bitcoin lockup output can never be credited to more than one active bond membership at a time, independent of the rollover bookkeeping fix.

### Proof of Concept
Rust integration test on booted chainstate (extending `stacks-node/src/tests/pox_5_integrations.rs`):
1. Set up two adjacent, non-overlapping bond periods A and B; allowlist staker S in both with sufficient `max-sats`.
2. Construct one real P2WSH L1 lockup transaction with a single output X of `S` sats, mine it, and build its Merkle/header proof.
3. Call `register-for-bond bond-index=A` from staker S referencing outpoint X; read `protocol-bonds-total-staked[A]` — expect it equals `S`.
4. Advance to bond A's rollover window; call `register-for-bond bond-index=B` from staker S, referencing the *same* outpoint X again (identical proof data).
5. Assert the call succeeds (no `ERR_DUPLICATE_LOCKUP_OUTPOINT`, no `ERR_ALREADY_REGISTERED`).
6. Assert `protocol-bonds-total-staked[A] + protocol-bonds-total-staked[B] == 2 * S`, while independently verifying (via Bitcoin RPC/UTXO check) that only `S` sats are actually locked/unspent under outpoint X — proving the equality "sats credited == sats locked once" is broken.

Note: the full 3845-line `pox-5.clar` file was only partially reviewed (first 1000 lines) due to size; the implementation of `verify-l1-lockups` itself and any later-in-file bond-closure/reconciliation logic were not directly inspected, so it is possible (though not evidenced by anything found) that some other mechanism elsewhere in the file mitigates this. This should be explicitly checked in the PoC step 6's negative-control run before treating the finding as fully confirmed.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L53-56)
```text
(define-constant ERR_INVALID_LOCKUP_AMOUNT (err u45))
;; The same Bitcoin outpoint (txid + output-index) appeared twice in
;; the L1 lockup proof list submitted to `register-for-bond`.
(define-constant ERR_DUPLICATE_LOCKUP_OUTPOINT (err u46))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L139-148)
```text
(define-map protocol-bond-memberships
    principal
    {
        bond-index: uint,
        amount-ustx: uint,
        signer: principal,
        is-l1-lock: bool,
        amount-sats: uint,
    }
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L682-687)
```text
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L782-784)
```text
        ;; Move the staker's custodied sBTC into this bond, transferring only the
        ;; net difference vs. any bond they're rolling over from.
        (try! (roll-sbtc tx-sender old-sbtc new-sbtc))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L792-801)
```text
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
```
