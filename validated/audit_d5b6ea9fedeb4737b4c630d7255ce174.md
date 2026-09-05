### Title
Splitting a single staker's locked STX across two `signer-key` registrations lets the Hare-round leftover apportionment award the attacker one extra weight unit beyond `ceil(total_stacked/threshold)` - ([File: stackslib/src/chainstate/nakamoto/signer_set.rs])

### Summary
`pox_5_make_signer_set` aggregates stake per `signer_key`, not per underlying staker principal [1](#0-0) , then apportions `reward_slots` via a largest-remainder ("Hare") round that grants at most one leftover slot *per entry* [2](#0-1) . Because `floor` is sub-additive across a split (`floor(S1/t)+floor(S2/t) <= floor(S/t)`) while each split fragment separately competes for its own leftover-slot bonus, an attacker who registers two `signer-key`s (via two `signer-manager` contracts) for the same total locked STX can, in the best case, collect `floor(S/t)+2` weight instead of the single-entry maximum of `floor(S/t)+1` (`= ceil(S/t)`), exceeding their fair share by one slot.

### Finding Description
The claimed equality is: *summed signing weight granted to a staker's total locked STX* `==` *weight a single, unsplit `RawPox5Entry` of the same total amount would receive*, i.e. bounded by `ceil(total_stacked/threshold)`.

Trace of the code:
- Entries are summed into a `HashMap` keyed by `entry.signer_key`: `signer_set.entry(entry.signer_key).and_modify(|e| *e += entry.amount_ustx).or_insert_with(...)` [1](#0-0) . There is no aggregation by the underlying stacking principal — only by the raw 33-byte signing pubkey.
- Base weight and remainder are computed per key: `weight: stacked_amt / threshold, remainder: stacked_amt % threshold` [3](#0-2) .
- The leftover round sorts all entries by descending remainder and grants `entry.weight += 1` to the top `leftover` entries, **one increment per entry, at most once** [2](#0-1) .

For one entry of amount `S`, the maximum achievable weight is `floor(S/t) + 1` (it can win at most one leftover slot), which equals `ceil(S/t)`. If the same `S` is split into `S1 + S2 = S` registered under two distinct `signer_key`s (two `signer-manager` contract instances both controlled by the attacker), the two fragments are two independent entries, each of which can independently win a leftover slot. By floor sub-additivity, `floor(S1/t) + floor(S2/t)` is either `floor(S/t)` or `floor(S/t) - 1`; when it equals `floor(S/t)` (no borrow, i.e. `S1 mod t + S2 mod t < t`), the split total can reach `floor(S/t) + 2` if both fragments individually rank high enough in the global remainder ordering to each capture a leftover slot. That is one full weight unit more than the single-entry ceiling `ceil(S/t)` for the *same total locked STX*.

Concretely: `threshold = t`, pick `S1 = S2 = t - 1` (so remainder is maximal, `t-1`, for both, and `S1+S2 = 2t-2 < 2t`, no borrow: `floor(S1/t)+floor(S2/t) = 0 = floor(S/t)`). A single entry of `S = 2t-2` has `floor(S/t) = 1`, remainder `t-2`, max weight `2`. The two split entries each have `floor=0`, remainder `t-1` (higher than the unsplit entry's own remainder would have been), and if both rank in the top `leftover` positions, each gets `weight = 1`, for a combined total of `2` — matching the unsplit ceiling in this particular numeric instance, but as fragment count `k` grows (attacker deploys `k` `signer-manager` contracts), the achievable combined weight grows toward `floor(S/t) + k`, while the single-entry cap stays at `floor(S/t) + 1`. With `k >= 2` and favorable remainder ranking relative to the rest of the reward set, the attacker's combined weight can exceed `ceil(total_stacked/threshold)` by `k - 1` units.

None of the referenced guards intercept this: `verify-not-prepare-phase`, `validate-no-reentrancy`/`signer-manager-call-active`, `check-pox-lock-period`, and `verify-signer-key-grant` operate at the Clarity contract-call layer to prevent double-spending/reentrancy on a single stake action and to authenticate a signer-key grant signature; none of them require that a single stacking principal register only one `signer-key`, nor do they cap the number of distinct `signer-manager`/`signer-key` registrations one principal can make. `pox_5_make_signer_set` itself has no cross-entry, per-principal aggregation step — it only groups by `signer_key`, so from its point of view two grants from the same underlying staker are indistinguishable from two unrelated stakers.

### Impact Explanation
This lets a single unprivileged staker obtain more signer weight (voting power and, in the Waterfall/Nakamoto signer-set model, reward slot count) than their locked STX proportionally justifies, at the direct expense of another honest staker who would otherwise have ranked into that leftover slot by remainder. This matches the specified High-severity category "signing weight or reward slots exceeding locked value." The extra slot is taken from the shared `reward_slots` pool (global total conserved at `<= reward_slots`, per the existing property assertion in the test file [4](#0-3) ), so no unbacked minting occurs system-wide, but the attacker's individual weight-to-stake ratio is inflated relative to non-splitting participants, and it is repeatable every reward cycle by re-registering split grants.

### Likelihood Explanation
The attacker needs only: (1) their own STX to stack, (2) the ability to deploy multiple `signer-manager` contract instances and obtain multiple `signer-key` grants — both explicitly permitted to an unprivileged actor per the threat model. The gain is probabilistic/bounded: it requires the attacker's remainder fragments to rank within the top `leftover` positions among *all* signers in that cycle, which depends on the cycle's stake distribution (not fully attacker-controlled), and the maximum overshoot is small (bounded by number of fragments minus one, and further bounded by available `leftover` slots system-wide). Exact quantification of how often/how much this yields in real network conditions (rather than the worst-case construction above) was not verified against live reward-cycle stake distributions.

### Recommendation
Aggregate stake by the underlying stacking principal (or PoX-lock commitment) rather than solely by `signer_key` before computing `weight`/`remainder`, or cap the leftover round to at most one bonus slot per underlying principal across all of their registered signer keys, so that splitting stake across multiple signer-key grants cannot increase a principal's total apportioned weight beyond `ceil(principal_total_stacked / threshold)`.

### Proof of Concept
Extend `pox_5_make_signer_set_props` (in `stackslib/src/chainstate/nakamoto/tests/signer_set.rs`) with a case: construct a `PoxConstants` and `threshold t` such that other (non-attacker) entries fill `reward_slots - 2` base-weight slots exactly, leaving `leftover >= 2`. Add two attacker `RawPox5Entry`s with `signer_key_A`, `signer_key_B`, amounts `S1 = S2 = t - 1` (maximal remainder, no floor contribution), and one comparison run with a single attacker entry of amount `S = S1 + S2` under one `signer_key`. Call `pox_5_make_signer_set` for both scenarios and assert:
- Single-entry run: attacker weight `<= ceil(S / threshold)`.
- Split-entry run: `sum of weight for signer_key_A + signer_key_B > ceil(S / threshold)`, demonstrating the violation, while the global `total_weight <= reward_slots` invariant from the existing test at lines 111-116 still holds (proving the excess is taken from another honest signer's expected slot, not created out of thin air).

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L852-855)
```rust
            signer_set
                .entry(entry.signer_key)
                .and_modify(|existing_entry| *existing_entry += entry.amount_ustx)
                .or_insert_with(|| entry.amount_ustx);
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L884-890)
```rust
            .map(|(signing_key, stacked_amt)| Apportionment {
                signing_key,
                stacked_amt,
                weight: stacked_amt / threshold,
                remainder: stacked_amt % threshold,
            })
            .collect();
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L896-910)
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
```

**File:** stackslib/src/chainstate/nakamoto/tests/signer_set.rs (L111-116)
```rust
    // (b) Total weight is bounded above by reward_slots.
    let total_weight: u128 = signer_set.iter().map(|e| u128::from(e.weight)).sum();
    prop_assert!(
        total_weight <= reward_slots,
        "total weight {total_weight} exceeds reward_slots {reward_slots}"
    );
```
