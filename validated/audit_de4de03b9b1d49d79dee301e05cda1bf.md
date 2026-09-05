### Title
Largest-remainder weight apportionment is keyed by `signer_key`, not by staker, letting one staker split locked STX across two signing keys to win two leftover slots for the price of one - ([File: stackslib/src/chainstate/nakamoto/signer_set.rs])

### Summary
`pox_5_make_signer_set` aggregates stacked amounts into `signer_set: HashMap<[u8; SIGNERS_PK_LEN], u128>` keyed strictly by `signer_key` [1](#0-0) . There is no aggregation by the underlying staker/origin principal, so a single staker who registers two distinct signer keys can split one locked-STX amount between them so that each half floors to zero base weight but carries a near-maximal remainder, letting both win the largest-remainder "leftover" round and capturing 2 units of weight instead of the 1 unit the same total stake would earn if kept under one key.

### Finding Description
The claimed equality is:

`weight(key_A) + weight(key_B) == floor((stacked(key_A) + stacked(key_B)) / threshold)` for `key_A, key_B` both economically controlled by the same staker.

The code computes, per unique `signer_key`:
```
weight: stacked_amt / threshold,
remainder: stacked_amt % threshold,
``` [2](#0-1) 
then distributes `leftover = reward_slots - sum(floor weights)` one unit at a time to the entries with the largest `remainder`, ties broken by ascending `signing_key`: [3](#0-2) 

If the staker locks a single amount `X` with `T <= X < 2T` (where `T` is `threshold`) under one key, that entry gets a guaranteed base `weight = 1` from the floor, consuming no leftover slot. If instead the staker splits `X` into two amounts `X/2` each under two different signing keys they control (e.g. each just under `T`), each entry floors to `weight = 0` but has a `remainder` close to `T` (near-maximal). Both entries then compete in, and can both win, the leftover round — which is a shared, capacity-limited pool for the *entire* signer set (`reward_slots`) — capturing `weight = 1` each, i.e. `2` total, for the identical locked amount that would have produced `1` under a single key. The extra unit is not created from nothing: it is taken from the fixed `reward_slots` pool at the expense of whichever other, unrelated signer had the next-largest remainder and would otherwise have won that slot.

None of the guards enumerated in the audit rules (`verify-not-prepare-phase`, `validate-no-reentrancy`/`signer-manager-call-active`, `check-pox-lock-period`, `verify-signer-key-grant`, the `<=` guards, `parse_pox_stake_result`) address this, because they govern lock validity and reentrancy, not per-staker aggregation across multiple signer keys in the reward-weight apportionment step. The computation in `pox_5_make_signer_set` has no notion of "staker" at all by the time it aggregates — it only ever sees `(signer_key, amount_ustx)` pairs from `RawPox5Entry`, produced by `get-amount-delegated-for-signer` per signer key [4](#0-3) , with no cross-check against a single origin principal.

### Impact Explanation
A staker gains signing weight (consensus block-signing threshold share) exceeding what their locked STX commitment would produce under normal apportionment, at the direct expense of another legitimate signer who loses the leftover slot they would otherwise have won. This matches the "signing weight or reward slots exceeding locked value" High-impact category: the attacker's own weight is inflated relative to their stake, and the fixed `reward_slots` pool is misallocated away from a signer whose stake more genuinely warranted it. The attack is repeatable every reward cycle in which the attacker re-registers/re-delegates under two (or more) signing keys with amounts engineered to sit just under `threshold` with a large remainder.

### Likelihood Explanation
Feasibility depends entirely on values the attacker fully controls: they need only (a) two signer keys they can generate for free, (b) enough STX to stack/delegate a given total, and (c) the ability to split the delegated amount between the two keys — all "unprivileged" actions (calling PoX-5's own delegate/stack entry points, no privileged role required). The attacker must know or estimate `threshold`, which is derived from total network-wide locked STX and `reward_slots` and is observable prior to the prepare-phase computation, so precise engineering of "just under `threshold`" amounts is feasible but requires timing/estimation around the cycle-threshold calculation. The gain per cycle is bounded (extra weight competes against other signers' remainders in the same leftover round, so it is not guaranteed to always win, and the size of the leftover pool limits how many extra units total can be grabbed this way).

### Recommendation
Aggregate stacked amounts by staker/origin principal (or by the tuple of all signer keys attributable to one underlying committed lock) before computing `weight`/`remainder`, rather than aggregating solely by `signer_key`; alternatively, cap the number of leftover-round wins attributable to a single origin principal, or require the reward-set computation to look up and merge amounts delegated by the same principal to different signer keys prior to apportionment.

### Proof of Concept
Rust test in `stackslib/src/chainstate/nakamoto/tests/signer_set.rs`:
1. Choose `reward_slots` and construct entries so that `threshold` resolves to a known `T`.
2. Add one `RawPox5Entry` with `signer_key = A`, `amount_ustx = T - 1` and another with `signer_key = B`, `amount_ustx = T - 1` (both nominally controlled by the same staker off-chain), keeping the rest of the network's stake fixed so `threshold == T`.
3. Call `NakamotoSigners::pox_5_make_signer_set` and assert that `weight(A) + weight(B) == (2*(T-1)) / T` (which floors to `1` for reasonable `T`).
4. Observe the actual result is `weight(A) + weight(B) == 2` (both win the leftover round due to near-`T` remainders), violating the assumed equality and demonstrating the split-key weight inflation, taken at the expense of whichever other single-key entry in the test set has the next-highest remainder and loses its expected leftover slot.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L424-439)
```rust
        // Total uSTX delegated to this signer for this cycle (sums STX-only
        // staking and protocol bonds; see signer-delegated-per-cycle).
        let amount_ustx = self
            .clarity
            .eval_method_read_only(
                &self.pox_contract,
                "get-amount-delegated-for-signer",
                &[lookup_signer.clone(), self.reward_cycle_clar.clone()],
            )
            .map_err(|e| PoxEntryParsingError::Skip(e.to_string()))?
            .expect_u128()
            .map_err(|_| {
                PoxEntryParsingError::Skip(
                    "get-amount-delegated-for-signer did not return uint".into(),
                )
            })?;
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L829-856)
```rust
        let mut signer_set = HashMap::new();
        let mut total_ustx_locked = 0u128;
        for entry_res in entries {
            let entry = match entry_res {
                Ok(x) => x,
                Err(PoxEntryParsingError::Skip(err_str)) => {
                    warn!(
                        "Error while iterating PoX-5 entries, impacting a single entry. Dropping entry from signer set";
                        "error" => err_str
                    );
                    continue;
                }
                Err(PoxEntryParsingError::Abort(err_str)) => {
                    error!(
                        "Abort-triggering error while iterating PoX-5 entries";
                        "error" => err_str
                    );
                    return Err(ChainstateError::PoxNoRewardCycle);
                }
            };

            total_ustx_locked += entry.amount_ustx;

            signer_set
                .entry(entry.signer_key)
                .and_modify(|existing_entry| *existing_entry += entry.amount_ustx)
                .or_insert_with(|| entry.amount_ustx);
        }
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L882-890)
```rust
        let mut apportioned: Vec<Apportionment> = signer_set
            .into_iter()
            .map(|(signing_key, stacked_amt)| Apportionment {
                signing_key,
                stacked_amt,
                weight: stacked_amt / threshold,
                remainder: stacked_amt % threshold,
            })
            .collect();
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L892-911)
```rust
        // Guaranteed `<= reward_slots` by the ceil quota, so leftover does not underflow.
        let assigned: u128 = apportioned.iter().map(|entry| entry.weight).sum();
        let mut leftover = reward_slots.saturating_sub(assigned);

        if leftover > 0 {
            // Largest fractional remainder wins the next slot; ties broken by signing_key
            // ascending so the apportionment is deterministic (and matches the final sort).
            apportioned.sort_by(|a, b| {
                b.remainder
                    .cmp(&a.remainder)
                    .then_with(|| a.signing_key.cmp(&b.signing_key))
            });
            for entry in apportioned.iter_mut() {
                if leftover == 0 {
                    break;
                }
                entry.weight += 1;
                leftover -= 1;
            }
        }
```
