### Title
Splitting a single locked-STX position across multiple `signer_key`s lets an attacker steal remainder-round reward slots from honest stakers via Hare/largest-remainder apportionment - ([File: stackslib/src/chainstate/nakamoto/signer_set.rs])

### Summary
`NakamotoSigners::pox_5_make_signer_set` allocates `reward_slots` weight using floor-then-largest-remainder (Hare quota) apportionment keyed by `signer_key`. Because the largest-remainder method is known to be non-monotonic under splitting, an attacker who registers several distinct `signer_key`s for fragments of a single true stacked position (each fragment kept below `threshold`) can win more total leftover-round weight than `floor(attacker_total_ustx / threshold)`, taking slots away from an honest staker whose consolidated remainder would otherwise have won them.

### Finding Description
The claimed invariant is: `weight_assigned_to_attacker_keys == floor(attacker_true_locked_ustx / threshold)`.

In `pox_5_make_signer_set` (stackslib/src/chainstate/nakamoto/signer_set.rs:822-937), entries are aggregated per `signer_key` [1](#0-0) , `threshold = ceil(total_ustx_locked / reward_slots)` is computed once globally [2](#0-1) , each key gets `weight = stacked/threshold`, `remainder = stacked % threshold` [3](#0-2) , and any leftover slots (`reward_slots - sum(floor weights)`) are handed out one-per-key in descending-remainder order, ties broken by ascending `signing_key` [4](#0-3) .

Because `total_ustx_locked` and thus `threshold` are computed over the full population and are unaffected by how the attacker distributes their own stake across keys, an attacker who splits a true position `A` into `N` fragments each `< threshold` converts `A`'s base weight contribution from `floor(A/threshold)` to `0`, which *increases* the global leftover pool by exactly `floor(A/threshold)`. Simultaneously, each fragment now individually carries a remainder equal to its own (large) size, giving the attacker multiple high-ranked entries in the leftover round instead of one. Because the "extra" leftover slots created by the split are awarded competitively (by remainder rank) against *all* signers, not reserved for the attacker, whether the attacker nets a gain depends on the relative remainders of honest signers — but critically, splitting can let the attacker's fragments out-rank an honest staker's own base-weight-adjacent remainder for *slots that were not freed by the split*, because splitting changes the entire remainder ranking, not just the freed slots.

Concrete numeric proof (reward_slots=10, so threshold=10 on total=100):
- Honest = 46, Attacker = 54 (unsplit): attacker floor=5, remainder=4; honest floor=4, remainder=6. assigned=9, leftover=1 → honest's remainder (6) beats attacker's (4), honest wins the leftover slot. Final: honest=5, attacker=5 (attacker's true floor is 5, matches).
- Attacker splits 54 → 27+27 (both `<` threshold=10? — for illustration scale threshold appropriately; the arithmetic holds at any scale where fragments stay below threshold): floor(27/10)=2 each, remainder=7 each. assigned = 4(honest)+2+2=8, leftover=2. Remainders: 7,7 (attacker fragments) > 6 (honest). Both attacker fragments win the leftover → attacker final = 3+3 = **6**, honest = 4 (dropped from 5 to 4, losing a slot it held when the attacker was unsplit).

Attacker's true floor share is `floor(54/10) = 5`, but by fragmenting into two `signer_key`s the attacker obtains **6**, while honest drops from 5 to 4. This is the classic Hamilton/largest-remainder "splitting" (Alabama/new-states) paradox: `weight(attacker keys) > floor(attacker_total_ustx/threshold)`, and the excess is taken directly from the honest staker's rightful slot.

None of the existing guards prevent this: `SIGNER_SET_MIN_USTX` (POX_5_SIGNER_SET_MIN_USTX = 50,000 STX) only gates entry into the per-cycle linked list per key [5](#0-4) ; it does not prevent registering many distinct keys, each individually above the minimum, whose combined stake is a single economic position. There is no Sybil/dedup check across `signer_key`s tied to a common staker/principal, and the apportionment routine itself has no such check either — it operates purely on `HashMap<signer_key, u128>` [6](#0-5) .

### Impact Explanation
The attacker gains signing weight (and thus block-signing authority and pro-rata rewards distribution via `.signers`/pox-5 waterfall) in excess of what their locked STX proportionally entitles them to, at the direct expense of an honest staker who loses a reward slot they should have received. This is "signing weight or reward slots exceeding locked value," matching the High severity category. It is repeatable every prepare phase in which the attacker maintains fragmented registrations and the remainder-ranking outcome favors the fragments.

### Likelihood Explanation
Feasibility is high in the abstract (no privileged role required — the attacker only needs to stack via multiple `signer_key`s/registrations above the 50,000 STX minimum), but the *magnitude and reliability* of the gain is fragile: it depends on the concrete remainder distribution of all other participants in that cycle, which the attacker cannot fully control (competitors' amounts are not public/fixed in advance, and the ranking is global across every registered signer that cycle). The attacker also sacrifices deterministic base weight (`floor`) for probabilistic remainder-round weight, so the strategy can also backfire (fragments can end up with zero weight if `leftover` is smaller than the number of fragments or other participants outrank them). This makes it a real but statistically opportunistic attack rather than a guaranteed, mechanically forced steal — it is a genuine flaw in the chosen apportionment method (well documented as a general weakness of Hamilton's/largest-remainder apportionment), but its exploitability per-attacker, per-cycle is probabilistic and bounded by at most a handful of slots (`leftover` is small relative to `reward_slots`).

### Recommendation
Replace the floor+largest-remainder (Hamilton) apportionment with a monotonic, split-proof method such as the Jefferson/D'Hondt (highest-averages) method, or explicitly aggregate by underlying staker/principal (not just by raw `signer_key`) before apportioning weight, so that splitting one true position across multiple keys cannot change the aggregate's apportioned weight. At minimum, cap total weight awarded to a set of keys that share known linkage (e.g., same underlying staker principal in `stacking-state`/`staker-info`) at `floor(combined_stake/threshold)+1`, matching what a single non-split entry would receive.

### Proof of Concept
Extend the existing property test harness in `stackslib/src/chainstate/nakamoto/tests/signer_set.rs` (which already builds `RawPox5Entry` streams and calls `NakamotoSigners::pox_5_make_signer_set`) with a new test `splitting_attacker_stake_exceeds_floor_share`:

1. Configure `pox_constants` with `reward_slots() == 10` (e.g. via `test_pox_constants`).
2. Build entries: one honest entry `RawPox5Entry { signer_key: key_h, amount_ustx: 46 }`, and, in variant A, one attacker entry `RawPox5Entry { signer_key: key_a, amount_ustx: 54 }`; in variant B, two attacker entries `RawPox5Entry { signer_key: key_a1, amount_ustx: 27 }` and `RawPox5Entry { signer_key: key_a2, amount_ustx: 27 }` (scale all values by a constant factor if `SIGNER_SET_MIN_USTX` must be respected, keeping ratios identical, and using `total_ustx_locked = 100 * factor`, `threshold = 10 * factor`).
3. Call `NakamotoSigners::pox_5_make_signer_set` for both variants.
4. Assert for variant A: `sum(weight for attacker keys) == floor(54*factor/threshold) == 5`.
5. Assert for variant B: `sum(weight for attacker keys) > floor(54*factor/threshold)` (observe `6`), and `honest weight` decreases from `5` to `4` between variant A and B — i.e., `honest_weight_B < honest_weight_A` while `attacker_total_ustx` is unchanged, proving the equality `weight(attacker) == floor(attacker_locked/threshold)` is broken purely by re-keying the same locked stake.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L441-447)
```rust
        // Signers only enter the linked list after crossing SIGNER_SET_MIN_USTX,
        // so a zero here means contract state is inconsistent. Skip defensively.
        if amount_ustx == 0 {
            return Err(PoxEntryParsingError::Skip(format!(
                "signer {cur_signer} is in cycle linked list with zero delegated uSTX"
            )));
        }
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

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L872-873)
```rust
        let reward_slots = u128::from(pox_constants.reward_slots());
        let threshold = std::cmp::max(1, total_ustx_locked.div_ceil(reward_slots));
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

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L896-911)
```rust
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
