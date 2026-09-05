Based on my investigation, no minimum-stacking-amount floor was found in `pox-5.clar` for individual `stake` entries, and `signer-manager.clar`'s `register-self` only prevents reuse of a single signer-key grant — it does not prevent one principal from deploying arbitrarily many distinct signer-manager contracts, each registering its own distinct `signer-key` via `grant-signer-key`/`register-signer`, and each staking a small, independently-chosen amount.

### Title
Largest-remainder ("Hare") apportionment in `pox_5_make_signer_set` lets an attacker gain reward-slot weight disproportionate to locked STX by splitting stake across many signer keys - ([File: stackslib/src/chainstate/nakamoto/signer_set.rs])

### Summary
`NakamotoSigners::pox_5_make_signer_set` aggregates stake per distinct `signer_key` and assigns weight via floor division by a network-wide threshold, then hands out any unassigned ("leftover") slots one-per-key to the largest fractional remainders [1](#0-0) . Because the leftover round is keyed by distinct `signer_key` and rewards whichever entries have the largest `stacked_amt % threshold`, an attacker who splits a fixed total `X` across `N` distinct signer-manager contracts (each with its own `signer_key`, each staking an amount just under `threshold`) can win up to `min(N, leftover)` extra weight units that a single consolidated entry of the same `X` would not receive.

### Finding Description
The intended equality is: total weight awarded to a principal's signers for a cycle == `floor(principal's total locked ustx / pox_ustx_threshold)`, i.e., weight should scale with actual locked value under a single global threshold, as verified in the property test at `check_make_signer_set` (`stackslib/src/chainstate/nakamoto/tests/signer_set.rs:118-139`) which itself documents that `total_weight == base + min(leftover, n_signers)`, not `floor(total/threshold)` alone [2](#0-1) .

The root cause is the Hare/largest-remainder apportionment design itself: `threshold = max(1, total_ustx_locked.div_ceil(reward_slots))` is a single global value computed over the whole cycle's stake [3](#0-2) , and each distinct `signer_key`'s base weight is `stacked_amt / threshold` with remainder `stacked_amt % threshold` [4](#0-3) . The leftover loop then sorts ALL distinct-key entries by descending remainder and hands out one weight unit each until leftover is exhausted [5](#0-4) .

An attacker controlling multiple signer-manager contracts (each independently `register-self`'d with its own `signer_key` and `auth-id`, per `contrib/core-contract-tests/contracts/signer-manager.clar:542-559`) can register N distinct small stakes, each sized just under `threshold` to maximize its remainder, rather than a single stake of the combined amount. Since `stacked_amt < threshold` for each entry, every entry's base weight floors to 0 (contributing nothing to `total_ustx_locked`'s honest "base" allocation), but each entry's remainder ≈ `threshold - 1` is near-maximal and will typically outrank genuine stakers' remainders in the descending sort, letting the attacker capture most or all of the network's leftover slots for a total locked amount `X` that, as a single entry, would yield `floor(X/threshold)` — potentially far less than the number of leftover slots captured. This exactly reproduces the documented "degenerate" scenario in `equal_stakes_exceeding_reward_slots_are_not_all_zeroed` (`stackslib/src/chainstate/nakamoto/tests/signer_set.rs:294-335`), but the test only demonstrates the (intended) fairness fix for genuinely distinct honest stakers — it does not check whether ONE principal manufacturing many artificial distinct keys can win the same outcome.

None of the referenced guards (`verify-not-prepare-phase`, `validate-no-reentrancy`/`signer-manager-call-active`, `check-pox-lock-period`, `verify-signer-key-grant`, `parse_pox_stake_result`) address this because they govern per-call authorization/timing, not the fairness of the apportionment across distinct signer keys, and I found no minimum-stacking-amount enforcement in `pox-5.clar` for individual `stake` calls that would floor `x_i` above a level large enough to prevent this splitting strategy — however, I was not able to fully confirm the absence of such a check across all of `pox-5.clar` and `pox_5_stake_entries`/`RawPox5Entry` parsing code, since grep for "minimum"/"threshold" keywords in `pox-5.clar` returned no matches and I could not directly inspect `pox_5_stake_entries`'s definition within the available iterations.

### Impact Explanation
This is a known theoretical weakness of largest-remainder (Hare quota) apportionment methods — they are not "split-proof" (unlike divisor methods such as D'Hondt/Sainte-Laguë) — and it manifests here as one principal capturing reward-slot/signing weight disproportionate to actual locked STX, matching the "High" impact category "signing weight or reward slots exceeding locked value." The attacker gains extra signer weight/reward-set membership (and thus outsized reward share and signing power) for the same locked STX, at the expense of leftover slots that would otherwise go to genuinely distinct, smaller-remainder honest stakers, or simply go unassigned. This is repeatable every reward cycle as long as the attacker maintains the split registrations and re-stakes appropriately.

### Likelihood Explanation
Exploitability depends heavily on network conditions during the cycle's prepare phase: the size of `leftover = reward_slots - base` (the "prize pool" available via the Hare round) is largely determined by the rest of the network's stake distribution, not solely by the attacker. If honest stakers already consume nearly all `reward_slots` via base (floor) weight, `leftover` will be small, capping the attacker's extra gain. The attack is most effective precisely in the "many roughly-equal small stakers" regime the Hare round was designed to rescue — which the code comments and regression test acknowledge as a real, expected network condition. I could not verify (due to exhausted search budget) whether a per-entry minimum-stake requirement in `pox-5.clar` bounds `N` or `x_i` tightly enough to make the attack impractical in production, which is a material factor for final severity/likelihood assessment.

### Recommendation
Replace or supplement the largest-remainder allocation with a split-resistant/monotone apportionment method (e.g., a divisor method such as Jefferson/D'Hondt or Webster/Sainte-Laguë), or aggregate remainder competition per-principal (across all `signer_key`s ultimately controlled by/paying out to the same STX-locking principal) rather than per-`signer_key`, so that splitting stake across multiple manager contracts cannot increase total awarded weight beyond `floor(total_locked_by_principal / threshold)`. At minimum, enforce a materially large per-entry minimum stacking amount in `pox-5.clar` so that `N` cannot exceed a small multiple of `reward_slots` for any bounded `X`.

### Proof of Concept
Extend `stackslib/src/chainstate/nakamoto/tests/signer_set.rs`'s `equal_stakes_exceeding_reward_slots_are_not_all_zeroed` with a scenario where all `N > reward_slots` entries use distinct `signer_key`s but are conceptually "owned" by a single attacker principal (e.g., add a test-only `owner` field or track ownership in the test), plus a smaller set of "honest" distinct-key entries with independent random amounts summing to `T_other`. Assert:
1. `single_key_weight = floor(attacker_total_X / pox_ustx_threshold)` (call `pox_5_make_signer_set` with the attacker's entries merged into one key) as the baseline.
2. `split_key_weight = sum of weight over the attacker's N distinct keys` from the real call with entries unmerged.
3. Assert `split_key_weight > single_key_weight`, demonstrating the divergence, and that `split_key_weight` approaches/equals `reward_slots` while `single_key_weight` (and `floor(X/threshold)`) remains near 0 for suitably small `X` relative to `T_other`.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L852-911)
```rust
            signer_set
                .entry(entry.signer_key)
                .and_modify(|existing_entry| *existing_entry += entry.amount_ustx)
                .or_insert_with(|| entry.amount_ustx);
        }

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
        let reward_slots = u128::from(pox_constants.reward_slots());
        let threshold = std::cmp::max(1, total_ustx_locked.div_ceil(reward_slots));

        struct Apportionment {
            signing_key: [u8; SIGNERS_PK_LEN],
            stacked_amt: u128,
            weight: u128,
            remainder: u128,
        }

        let mut apportioned: Vec<Apportionment> = signer_set
            .into_iter()
            .map(|(signing_key, stacked_amt)| Apportionment {
                signing_key,
                stacked_amt,
                weight: stacked_amt / threshold,
                remainder: stacked_amt % threshold,
            })
            .collect();

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

**File:** stackslib/src/chainstate/nakamoto/tests/signer_set.rs (L118-139)
```rust
    // (b') Conservation: the base weights (floor(stacked/threshold)) sum to `base`, leaving
    //      `leftover = reward_slots - base` slots. The Hare round hands one slot to each of
    //      `min(leftover, N)` signers (largest remainder first), so the total weight assigned
    //      is exactly `base + min(leftover, N)`. `base <= reward_slots` is guaranteed by the
    //      ceil quota, so `leftover` does not underflow.
    let base: u128 = aggregated.values().map(|amt| amt / threshold).sum();
    prop_assert!(
        base <= reward_slots,
        "base weight {base} exceeds reward_slots {reward_slots} (ceil-quota invariant broken)"
    );
    let leftover = reward_slots - base;
    let n_signers = aggregated.len() as u128;
    let expected_total_weight = base + std::cmp::min(leftover, n_signers);
    prop_assert_eq!(
        total_weight,
        expected_total_weight,
        "total weight {} != base {} + min(leftover {}, signers {})",
        total_weight,
        base,
        leftover,
        n_signers
    );
```
