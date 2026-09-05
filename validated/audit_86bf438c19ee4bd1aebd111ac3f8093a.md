### Title
Sybil signer-key splitting in `pox_5_make_signer_set` lets an attacker capture disproportionate signing weight via the largest-remainder "leftover" round - ([File: stackslib/src/chainstate/nakamoto/signer_set.rs])

### Summary
`pox_5_make_signer_set` groups stacked amounts by `signer_key` [1](#0-0)  and then apportions `reward_slots` weight using a largest-remainder ("Hare quota") method that hands out one leftover slot per distinct key in descending remainder order [2](#0-1) . Because nothing ties multiple `signer_key`s to the same economic beneficiary or bounds how many distinct signing keys one attacker may register, an attacker can split their real stacked STX across many sock-puppet keys, each sized just under the per-cycle `threshold`, so every entry floors to weight `0` but wins the maximal possible `remainder` — letting the attacker dominate the "leftover" pool of slots far beyond their proportional share of `total_ustx_locked`.

### Finding Description
The code computes, for each distinct `signer_key`, `weight = stacked_amt / threshold` and `remainder = stacked_amt % threshold` [3](#0-2) , then distributes `leftover = reward_slots - assigned` extra `+1` weight units to entries sorted by descending remainder [4](#0-3) . The intended invariant (per the code's own comment) is that the largest-remainder round only ever awards, in aggregate, an amount bounded by one "quota unit" of slack per real stake position [5](#0-4) . This invariant silently assumes each `signer_key` corresponds to one real, indivisible staking position.

That assumption is false: `signer_key` is attacker-chosen and free to generate, and the aggregation in `pox_5_make_signer_set` is done per `signer_key`, not per beneficial owner/principal [6](#0-5) . An attacker who controls a fixed total of stacked STX `S` can register it across `K` sock-puppet principals with `K` distinct signer keys, each with `amount_ustx = A` where `A < threshold` (down to the entry-level minimum). Each such entry has `weight = 0` (base) but `remainder = A`, so all `K` entries compete for — and, if `A` is close to the maximum possible remainder or simply large relative to other real stakers' remainders, will win — up to `min(K, leftover)` of the leftover slots.

For a fixed total `S`, splitting into more, smaller pieces (`K` large, `A` small, down to the entry minimum) strictly increases the number of "free" remainder tickets the attacker holds, while `floor(S/threshold)` (the true proportional share) stays essentially fixed. The achievable excess weight is therefore `min(K, leftover) - floor(S/threshold)`, which is unbounded by the number of sock-puppet keys the attacker is willing to create (bounded in practice only by the entry-minimum lock size and the size of the global `leftover` pool, which can be as large as `reward_slots` in low-participation cycles). This breaks the equality the design relies on — that a signer's total weight tracks its proportional share of `total_ustx_locked` within a single +1 rounding unit — because that +1 bound only holds per distinct `signer_key`, not per attacker-controlled aggregate stake.

No existing guard prevents this: `verify-signer-key-grant` and related pox-5.clar checks only bind one signer-key grant to the tx-sender that requests it; they do not prevent one beneficial owner from controlling arbitrarily many tx-senders/principals each registering its own signer key, which is squarely within the stated attacker capability ("any Stacks account with its own STX ... who can call any pox-5 entry point").

### Impact Explanation
The attacker gains signing weight / reward-slot allocation (`NakamotoSignerEntry.weight`) exceeding their true proportional share of locked STX, at the direct expense of honest signers who are crowded out of the leftover-slot round [7](#0-6) . This is repeatable every reward cycle for as long as the attacker maintains the sock-puppet stacking positions, and scales with the number of sock-puppet keys created, matching the "High" impact category (signing weight or reward slots exceeding locked value).

### Likelihood Explanation
The attack requires only: (1) real STX the attacker already controls, split and locked under many distinct principals with distinct signer keys, each sized below `threshold` (down to the pox-5 minimum stake amount); (2) normal use of the pox-5 stacking entry points, which the stated attacker is explicitly permitted to call. No privileged role, timing exploit beyond normal cycle registration, or protocol-level defect is needed — it is a straightforward Sybil/list-splitting manipulation of a largest-remainder apportionment method, feasible at low marginal cost (extra keypairs and transactions only) beyond the STX the attacker was going to lock anyway.

### Recommendation
Aggregate stacked amounts by beneficial owner/principal (or otherwise cap the number of distinct signer keys / leftover tickets one economic actor may hold) before running the largest-remainder apportionment, or bound the largest-remainder round so a single controlling entity cannot claim more than one leftover slot regardless of how many `signer_key`s it registers.

### Proof of Concept
Add a test alongside the existing `pox_5_make_signer_set` tests in `stackslib/src/chainstate/nakamoto/tests/signer_set.rs`:
1. Construct real (non-sock-puppet) `RawPox5Entry` records representing honest stakers whose combined stake yields a `threshold` T.
2. Construct `K` sock-puppet `RawPox5Entry` records, each with a distinct `signer_key` and `amount_ustx = A` where `A < T` (e.g., `A` = entry minimum), summing to the attacker's real total stake `S`.
3. Call `pox_5_make_signer_set` over the combined entry stream.
4. Assert: sum of `weight` for the attacker's `K` signing keys `> floor(S / threshold) + 1`, and separately assert that increasing `K` (for the same fixed `S`) strictly increases the attacker's total captured weight, demonstrating the excess is unbounded by number of sock-puppet keys rather than capped at the intended single +1 rounding unit.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L850-856)
```rust
            total_ustx_locked += entry.amount_ustx;

            signer_set
                .entry(entry.signer_key)
                .and_modify(|existing_entry| *existing_entry += entry.amount_ustx)
                .or_insert_with(|| entry.amount_ustx);
        }
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L858-871)
```rust
        // Allocate `reward_slots` weight across signers in proportion to stake using the
        // a largest-remainder method:
        //
        // The threshold is `ceil(total / reward_slots)`.
        //
        // Flooring each signer's `stacked / threshold` assigns a base weight where the sum is `<= reward_slots`
        // (the ceil makes `total/threshold <= reward_slots`).
        //
        // This leaves some unassigned ("leftover") slots, which are handed out one-per-signer
        //  in descending fractional-remainder order (ties broken by pubkey-sort order).
        //
        // This avoids degenerate modes of the floor-and-drop scheme: when more than
        // `reward_slots` distinct signers hold roughly equal stake, every base weight floors to
        // 0, and without the leftover round the entire signer set could be dropped.
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

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L913-927)
```rust
        let mut signer_set: Vec<_> = apportioned
            .into_iter()
            .filter_map(|entry| {
                if entry.weight == 0 {
                    return None;
                }
                let weight = u32::try_from(entry.weight)
                    .expect("CORRUPTION: Stacker claimed > u32::max() reward slots");
                Some(NakamotoSignerEntry {
                    signing_key: entry.signing_key,
                    stacked_amt: entry.stacked_amt,
                    weight,
                })
            })
            .collect();
```
