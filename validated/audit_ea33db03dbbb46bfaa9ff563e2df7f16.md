### Title
Largest-remainder Hare round in `pox_5_make_signer_set` grants extra signing-weight slots to a single economic actor who splits stake across multiple `signer_key`s - ([File: stackslib/src/chainstate/nakamoto/signer_set.rs])

### Summary
`pox_5_make_signer_set` aggregates PoX-5 entries strictly by `signer_key`, then apportions `reward_slots` using floor division plus a largest-remainder ("Hare") round that grants at most one extra slot *per distinct key*, not per staker/principal. Because the per-entry remainder cap of +1 is independent of remainder magnitude, an actor who splits a single stacked amount into two different `signer_key`s under two different signer-manager identities can win two Hare-round slots instead of the single slot the same amount would win as one aggregated entry, whenever the split does not cost a floor-division unit (i.e., `r1 + r2 < threshold`).

### Finding Description
The apportionment logic aggregates by key with a `HashMap` and computes weight independently per key: [1](#0-0) 

The floor "base" weight is superadditive across a split (`floor(A1/t)+floor(A2/t) <= floor((A1+A2)/t)`), so splitting can only *lose* base weight, never gain it. But the leftover ("Hare") round then hands exactly one extra slot to each distinct entry ranked by remainder, capped at 1 per entry regardless of how large that entry's remainder is: [2](#0-1) 

For a combined single entry of amount `A = A1 + A2`, when `r1 = A1 mod t` and `r2 = A2 mod t` satisfy `r1 + r2 < t` (no base-weight loss from splitting), the combined entry's own remainder is `r1 + r2` and it can win at most 1 leftover slot. If instead the two amounts are registered under two different `signer_key`s (which the attacker can freely choose, e.g. by deploying and controlling two signer-manager identities that route to two keys they hold), each split entry independently competes in the same Hare ranking and each can independently win its own +1 slot — up to 2 slots for the same base weight that the single aggregate entry could win only 1 slot for. This is confirmed by the project's own invariant test, which asserts per-entry weight is bounded to `{base, base+1}` *per key* — it does not, and structurally cannot, bound the sum across multiple keys held by one controller: [3](#0-2) 

The broken equality: the question's claimed invariant is `weight(attacker's keys) == floor(stacked_amt/threshold) [+0 or 1]`, never exceeding what one aggregate delegation would earn. Tracing the code shows this holds *per signer_key* but not *per controlling principal*, because aggregation key is `entry.signer_key` (a raw pubkey), with no linkage back to the staker/principal identity for fairness purposes: [4](#0-3) 

None of the guards named in the question address this: `verify-signer-key-grant`/grant mechanisms in `pox-5.clar` establish key *ownership* (that the caller controls the private key), not *uniqueness of controlling principal across the whole signer set*; `check-pox-lock-period`, `validate-no-reentrancy`/`signer-manager-call-active`, and `verify-not-prepare-phase` govern staking legitimacy and timing, not the fairness of the largest-remainder apportionment across multiple keys. The `<=` guards and `parse_pox_stake_result` bound total weight globally at `reward_slots` (confirmed by the `total_weight <= reward_slots` property test), but that is a global cap, not a per-attacker fairness bound — it does not prevent one attacker from displacing an honest signer's leftover slot.

### Impact Explanation
An attacker who splits their locked STX across two (or more) `signer_key`s they control can obtain one additional PoX-5 signing weight slot beyond what a single aggregated delegation of the same locked amount would earn. Since signer weight determines block-signing/voting influence and reward-slot share in the Nakamoto signer set, this directly matches "signing weight or reward slots exceeding locked value" (High). The extra slot is taken from the pool of `reward_slots`, so it comes at the direct expense of the honest signer who would otherwise have won that Hare-round slot, diluting their signing weight/rewards relative to their locked-STX share. The attack is repeatable each reward-cycle prepare-phase computation, as long as the attacker maintains the split registration and the remainder arithmetic condition (`r1+r2 < threshold`, and both r1, r2 individually rank within the top `leftover` remainders) holds.

### Likelihood Explanation
Preconditions: attacker needs (1) enough locked STX to produce a base amount `A`, (2) the ability to register that amount under two distinct `signer_key`s via two signer-manager identities (permitted — no code restricts a single staker/principal to one `signer_key`), and (3) favorable remainder arithmetic, i.e., choosing split amounts `A1, A2` such that `A1 mod t` and `A2 mod t` both individually beat competing signers' remainders while `(A1 mod t)+(A2 mod t) < t`. This requires knowledge/estimation of `threshold` (computable in advance from public stacked totals) and of competing signers' remainders (also derivable from public on-chain stacking data before the prepare-phase cutoff). This is feasible for a sophisticated but unprivileged attacker and costs only the normal cost of staking plus deploying a second signer-manager contract — no privileged role is required.

### Recommendation
Change the largest-remainder round in `pox_5_make_signer_set` to aggregate and rank by controlling principal (or otherwise dedupe/attribute Hare-round eligibility to one slot per unique staker/delegator identity rather than per raw `signer_key`), or cap total leftover slots any single principal can win to `1`, regardless of how many distinct `signer_key`s they register. Alternatively, replace the largest-remainder method with an apportionment method invariant to bloc-splitting (e.g., a deterministic method that computes leftover eligibility from the *aggregated* remainder per underlying staker rather than per key).

### Proof of Concept
Rust unit test added alongside `stackslib/src/chainstate/nakamoto/tests/signer_set.rs`:
1. Construct `pox_constants` with `reward_slots() == N` (e.g., 4).
2. Construct one honest signer entry with remainder `r_honest` chosen such that it would normally win the 2nd leftover slot when the attacker registers as a single combined entry.
3. Case A (combined): register attacker's full amount `A` under a single `signer_key_c`; call `pox_5_make_signer_set`; record `weight_c` for that key.
4. Case B (split): register `A1` and `A2` (`A1+A2 == A`, `(A1 % threshold) + (A2 % threshold) < threshold`) under two distinct `signer_key_1`/`signer_key_2`; call `pox_5_make_signer_set`; record `weight_1 + weight_2`.
5. Assert `weight_1 + weight_2 > weight_c` (violating the claimed invariant that splitting never increases total weight beyond one honest aggregate delegation), and separately assert the honest signer's weight decreases or is displaced between Case A and Case B, demonstrating the honest signer's slot was captured by the attacker's split.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L850-890)
```rust
            total_ustx_locked += entry.amount_ustx;

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

**File:** stackslib/src/chainstate/nakamoto/tests/signer_set.rs (L141-159)
```rust
    // (c) For each output entry: stacked_amt matches the aggregated input, weight is in
    //     {floor(stacked/threshold), floor(stacked/threshold) + 1} (the Hare round adds at
    //     most one slot), and weight >= 1.
    let mut seen: HashMap<[u8; SIGNERS_PK_LEN], ()> = HashMap::new();
    for entry in &signer_set {
        seen.insert(entry.signing_key, ());
        let aggregated_amt = *aggregated.get(&entry.signing_key).ok_or_else(|| {
            TestCaseError::fail("output entry signing_key not present in input aggregation")
        })?;
        prop_assert_eq!(entry.stacked_amt, aggregated_amt);
        let base_weight = aggregated_amt / threshold;
        prop_assert!(
            u128::from(entry.weight) == base_weight || u128::from(entry.weight) == base_weight + 1,
            "weight {} not in {{{base_weight}, {}}}",
            entry.weight,
            base_weight + 1
        );
        prop_assert!(entry.weight >= 1, "filtered weight==0 entry leaked through");
    }
```
