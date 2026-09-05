### Title
Same L1 BTC lockup proof can be credited to two different bonds via rollover, double-counting one Bitcoin commitment - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`register-for-bond`'s L1 proof-consumption tracking is scoped per call (`validate-l1-lockup`'s outpoint dedup) and per `{bond-index, staker}` (`protocol-bond-allowances`), with no persistent, UTXO-keyed record of which outpoints have already been credited. Combined with the fact that rolling a staker from one bond into another does not tear down the old bond's per-cycle sats totals, the same BTC lockup proof can be submitted to a second, different `bond-index` and be counted again.

### Finding Description
The equality that must hold: `sum(amount-sats credited across all protocol-bonds-total-staked / bond-cycle shares) for a given Bitcoin outpoint == that outpoint's actual locked value`, credited once.

In `register-for-bond` [1](#0-0) , `sats-total` is derived from `verify-l1-lockups`, and duplicate-outpoint protection (`ERR_DUPLICATE_LOCKUP_OUTPOINT`, `u46`) is implemented as a fold-based dedup **inside a single call's output list only** (confirmed by the integration test's own comment: "the dedup check sits inside the fold... trips before the post-fold sum check") [2](#0-1) . There is no map in `pox-5.clar` that records a Bitcoin outpoint as globally "consumed" across separate transactions or across bond indices — allowlist/consumption state that does exist is keyed by `{bond-index, staker}` via `protocol-bond-allowances` [3](#0-2) , and membership is keyed only by `tx-sender` in `protocol-bond-memberships` (one entry per staker, overwritten on every `register-for-bond` call) [4](#0-3) .

When a staker who already has `existing-membership` for bond B0 calls `register-for-bond` again for a different `bond-index` B1 with the *same* proof `P`, the code path explicitly treats this as a "roll-over" and documents that it does **not** remove the old bond's per-cycle shares: "A roll-over from an ending bond ADDS the new bond's shares but does NOT tear down the old bond's per-cycle shares/delegation" [5](#0-4) . `protocol-bonds-total-staked` for B0 was already incremented by `sats-total` on the first call [6](#0-5) , and the second call increments B1's total by the same `sats-total` again, while `protocol-bond-memberships` is simply overwritten to point at B1 [7](#0-6) . Because `verify-l1-lockups`/`validate-l1-lockup` re-verify proof `P` against the Bitcoin header/merkle path but consult no cross-bond, UTXO-keyed consumption record, this re-verification succeeds a second time.

Existing test coverage only exercises: (a) triple-submission of the same outpoint *within one call* (blocked by the in-fold dedup), and (b) re-submitting the same proof to the *same* `bond-index` twice (blocked because both test calls use `bond-index = 0`, tripping `ERR_ALREADY_REGISTERED`) [8](#0-7) [9](#0-8) . Neither test exercises the cross-bond-index reuse scenario described in the question, and I found no guard in the reviewed code sections that keys consumption off the Bitcoin outpoint itself independent of `bond-index`.

I was not able to fully verify, within the available tool budget, whether `ERR_ROLLOVER_TOO_EARLY` (`u48`) or other timing/ordering checks (`ERR_INVALID_BOND_PERIOD_ORDERING`, `ERR_ACTIVE_BOND_NOT_INCLUDED`) incidentally prevent this specific double-credit by restricting *when* a rollover into B1 may occur relative to B0's lock/unlock schedule. That check's exact semantics were not read in this session, so it remains an open question whether it closes this gap or only regulates timing without preventing the same UTXO from being credited into two bonds' staked totals.

### Impact Explanation
If unaffected by an unverified timing guard, a single Bitcoin lockup would be double-counted: `protocol-bonds-total-staked` (and the associated per-cycle signer/bond shares via `add-staker-to-bond-cycles`) for both B0 and B1 would each reflect the full `sats-total` from one underlying UTXO, inflating signer-weight/reward-eligibility totals for two bonds simultaneously from a single locked-BTC commitment. This matches the Critical category: "double-counting a commitment ... counted twice."

### Likelihood Explanation
Preconditions: attacker (an allowlisted staker on both B0 and B1, which the question grants as pre-existing admin-controlled state) needs no privileged role beyond normal `register-for-bond` calls; cost is limited to transaction fees for two `register-for-bond` calls using the same proof bytes. Repeatability depends on how many bonds the staker is allowlisted for and, critically, on the unverified rollover-timing guard (`ERR_ROLLOVER_TOO_EARLY`) — if that guard does not tie rollover eligibility to actual BTC-unlock/consumption state, the attack is repeatable across every bond the staker is allowlisted on.

### Recommendation
Add a persistent, globally-scoped map keyed by the Bitcoin outpoint (txid + output-index) that is checked and marked-consumed inside `verify-l1-lockups`/`validate-l1-lockup`, independent of `bond-index` or `staker`. Additionally, when processing a roll-over in `register-for-bond`, decrement the prior bond's `protocol-bonds-total-staked` and per-cycle shares by the amount being rolled over so a single credited amount is never simultaneously reflected in two bonds' totals.

### Proof of Concept
Rust integration test extending `check_pox_5_register_for_bond_l1_lockup_lifecycle`-style harness in `stacks-node/src/tests/pox_5_integrations.rs`:
1. `setup-bond` for B0 and B1 (bond-index 0 and 1), allowlisting the same staker on both.
2. Build one real L1 BTC lockup proof `P` for a single UTXO of `S` sats.
3. Call `register-for-bond(0, signer, amount_ustx, P, none)` — assert success, and assert `get-bond-total-staked(0) == S` (or equivalent read-only for `protocol-bonds-total-staked`).
4. Call `register-for-bond(1, signer, amount_ustx, P, none)` from the same staker.
5. Assert equality both sides: total sats credited for outpoint == `S` (once). If step 4 succeeds and `get-bond-total-staked(0) + get-bond-total-staked(1) == 2*S` (i.e., B0's total was not decremented), the equality is broken and the vulnerability is confirmed. If step 4 reverts (e.g., with `ERR_ROLLOVER_TOO_EARLY`) in all reachable timing windows, the finding is invalidated — this determination requires the code for that guard, which was not available in this session.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L616-624)
```text
        (asserts!
            (map-insert protocol-bond-allowances {
                bond-index: bond-index,
                staker: (get staker staker-item),
            }
                (get max-sats staker-item)
            )
            ERR_STAKER_ALREADY_ADDED
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L642-676)
```text
(define-public (register-for-bond
        (bond-index uint)
        (signer-manager <signer-manager-trait>)
        (amount-ustx uint)
        ;; Their BTC lockup info. If the response is `ok`, then
        ;; this is a list of outputs corresponding to their timelocks.
        ;; If the response is `err`, this is the amount of sBTC (in sats)
        ;; that they want to lock.
        (btc-lockup (response {
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
        }
            uint
        ))
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L679-679)
```text
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-792)
```text
        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
            amount-sats: sats-total,
        })
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L793-801)
```text
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

**File:** stacks-node/src/tests/pox_5_integrations.rs (L1417-1420)
```rust
/// - submitting the same lockup outpoint three times in the L1 proof list
///   is rejected with `ERR_DUPLICATE_LOCKUP_OUTPOINT` (u46) — the per-output
///   dedup inside `validate-l1-lockup` trips before the post-fold sum check,
///   and the failure leaves the staker with no bond membership and no STX lock
```

**File:** stacks-node/src/tests/pox_5_integrations.rs (L1955-1962)
```rust
        "register-for-bond",
        &[
            Value::UInt(0),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            l1_dup_lockup_arg,
            Value::none(),
        ],
```

**File:** stacks-node/src/tests/pox_5_integrations.rs (L2098-2116)
```rust
    // 5) A second `register-for-bond` from the same staker via the L1 path
    // must still fail with `ERR_ALREADY_REGISTERED` (u9) — the duplicate
    // check sits after `verify-l1-lockups` runs.
    test_observer::clear();
    let dup_tx = make_contract_call(
        &staker_sk,
        2,
        register_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "register-for-bond",
        &[
            Value::UInt(0),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            l1_lockup_arg,
            Value::none(),
        ],
```
