### Title
Signer weight in `make_signer_set` is computed independently of the reward-address-level `missed_slots` auto-unlock decision in `make_reward_set`, allowing a signer to retain full-cycle signing weight backed by STX that is auto-unlocked mid-cycle - (File: stackslib/src/chainstate/stacks/boot/mod.rs)

### Summary
`make_reward_set` decides whether a stacker's locked STX is "missed" (and thus eligible for early auto-unlock) strictly on a per-`reward_address` basis, while `make_signer_set` independently aggregates `amount_stacked` purely by `signer` key across the whole input set. A staker can split one economic position into two `stacker`/`reward_address` pairs, each individually below `threshold`, to push both contributions into `missed_slots` (full early unlock) while the combined amount under the shared `signing_key` still clears the `weight == 0` filter in `make_signer_set`, producing live signer weight not backed by STX that remains locked for the cycle.

### Finding Description
The broken equality: *STX weight granted to `signing_key`* should be backed by *STX actually remaining locked for the cycle under that signing key*. `make_reward_set` groups entries by `reward_address` (sorted/merged via `addresses.sort_by_cached_key` and the inner `while addresses.last()...` loop at [1](#0-0) ) and computes `slots_taken = stacked_amt / threshold` per address group. If `slots_taken == 0` and the group has a `stacker` pointer, all of that group's stacked amount is pushed into `missed_slots`, which (in epochs where `supports_pox_missed_slot_unlocks()` is true) marks it for auto-unlock: [2](#0-1) .

Separately, `make_signer_set` aggregates `amount_stacked` by `signer` key across *all* entries regardless of `reward_address`, and grants `weight = stacked_amt / threshold` whenever the summed amount clears the threshold: [3](#0-2) .

Because these two aggregations use different keys (`reward_address` vs `signer`), an attacker who controls two `stacker` principals (each backing a distinct `reward_address`) under one shared `signing_key` can structure both contributions to be individually below `threshold`. Each is then classified as fully "missed" and eligible for early auto-unlock, while the shared `signing_key`'s summed `stacked_amt` in `make_signer_set` still exceeds `threshold`, producing `weight >= 1` for the entire reward cycle. `RewardSet` bundles both the `signers` vector and `PoxStartCycleInfo.missed_reward_slots` from a single call to `make_reward_set` (which internally calls `make_signer_set`) at [4](#0-3) , so the divergence is baked into the reward set for the whole cycle - there is no later reconciliation step in this file that reduces `weight` when a `missed_reward_slots` entry is later processed for auto-unlock.

Contrast with the non-split case: if the same total amount were stacked to a single `reward_address`, `slots_taken >= 1` and the `if slots_taken == 0` branch is never entered, so no auto-unlock occurs and the STX stays locked normally for the full cycle, matching its signer weight. Splitting the same total amount into two sub-threshold `reward_address`/`stacker` pairs sacrifices the reward slot but converts the entire position into "missed" (fully eligible for auto-unlock) while the signer weight computed from the pre-split aggregate total is unaffected.

### Impact Explanation
The signer gains signing weight (voting/attestation power in the Nakamoto signer set) for a full reward cycle that is not backed by STX remaining actually locked, since both contributing `stacker` records are flagged for early auto-unlock. This matches the "signing weight ... exceeding locked value" High-impact category: the attacker keeps liquidity of their STX (able to transfer/spend/re-stack it) while still exercising signer influence proportional to the pre-unlock stacked amount. This is repeatable every reward cycle by any staker willing to forgo the marginal reward-slot BTC payout from consolidating into one address, and does not require any privileged role - only ordinary `stack-stx`/`stack-aggregation-commit`-style calls creating two sub-threshold, same-signer positions.

### Likelihood Explanation
Preconditions are modest: the target epoch must support `supports_pox_missed_slot_unlocks()` (true in current epochs per [5](#0-4) ), and the attacker needs two distinct `stacker` principals each stacking a sub-threshold amount to two different reward addresses, both registering the same `signer` key. This is straightforwardly achievable by an unprivileged staker with two accounts. No prepare-phase or reentrancy guard in the cited Rust code path addresses the cross-key/cross-address aggregation mismatch. I could not fully trace the Clarity-side consumer of `missed_reward_slots` (the actual auto-unlock execution contract, likely pox-4/pox-5) within the available tool budget, so the exact on-chain unlocking mechanics and any possible additional Clarity-level guard were not directly confirmed - this should be verified further before treating the finding as fully proven end-to-end.

### Recommendation
Compute `weight` in `make_signer_set` using only the `amount_stacked` of contributions that actually earned a reward slot (i.e., exclude or discount amounts belonging to entries whose `reward_address` group fell into `missed_slots`), or alternatively, key the missed-slot/auto-unlock decision by `signer` in addition to `reward_address` so that a signer's aggregate weight and its auto-unlock-eligible STX are computed over the same grouping key.

### Proof of Concept
Rust test in the spirit of `stackslib/src/chainstate/stacks/tests/reward_set.rs`:
1. Construct two `RawRewardSetEntry`s with the same `signer` (`signing_key`) but distinct `stacker` principals and distinct `reward_address`es, each with `amount_stacked` set to `0.75 * threshold` (so each is individually below `threshold`).
2. Call `StacksChainState::make_reward_set(threshold, entries, epoch_id_supporting_missed_slot_unlocks)`.
3. Assert both entries appear in `result.start_cycle_state.missed_reward_slots` (i.e., both are marked for auto-unlock, matching current code at lines 1143-1177).
4. Assert `result.signers` contains a `NakamotoSignerEntry` for the shared `signing_key` with `weight >= 1` (matching current code at lines 1039-1065).
5. Assert the equality that should hold but does not: `weight == 0` OR the STX backing that weight is excluded from `missed_reward_slots` - currently both assertions in steps 3 and 4 pass simultaneously, proving the STX is simultaneously "missed"/auto-unlock-eligible and backing a live nonzero signer weight for the cycle.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/mod.rs (L1039-1065)
```rust
        let mut signer_set = BTreeMap::new();
        for entry in entries.iter() {
            let signing_key = entry
                .signer
                .expect("BUG: signing keys should all be set in reward-sets with any signing keys");
            if let Some(existing_entry) = signer_set.get_mut(&signing_key) {
                *existing_entry += entry.amount_stacked;
            } else {
                signer_set.insert(signing_key, entry.amount_stacked);
            };
        }

        let mut signer_set: Vec<_> = signer_set
            .into_iter()
            .filter_map(|(signing_key, stacked_amt)| {
                let weight = u32::try_from(stacked_amt / threshold)
                    .expect("CORRUPTION: Stacker claimed > u32::max() reward slots");
                if weight == 0 {
                    return None;
                }
                Some(NakamotoSignerEntry {
                    signing_key,
                    stacked_amt,
                    weight,
                })
            })
            .collect();
```

**File:** stackslib/src/chainstate/stacks/boot/mod.rs (L1088-1129)
```rust
        // the way that we sum addresses relies on sorting.
        if epoch_id < StacksEpochId::Epoch21 {
            addresses.sort_by_cached_key(|k| k.reward_address.bytes());
        } else {
            addresses.sort_by_cached_key(|k| k.reward_address.to_burnchain_repr());
        }

        let signer_set = Self::make_signer_set(threshold, &addresses);

        while let Some(RawRewardSetEntry {
            reward_address: address,
            amount_stacked: mut stacked_amt,
            stacker,
            ..
        }) = addresses.pop()
        {
            let mut contributed_stackers = vec![];
            if let Some(stacker) = stacker.as_ref() {
                contributed_stackers.push((stacker.clone(), stacked_amt));
            }
            // Here we check if we should combine any entries with the same
            //  reward address together in the reward set.
            // The outer while loop pops the last element of the
            //  addresses vector, and here we peak at the last item in
            //  the vector (via last()). Because the items in the
            //  vector are sorted by address, we know that any entry
            //  with the same `reward_address` as `address` will be at the end of
            //  the list (and therefore found by this loop)
            while addresses.last().map(|x| &x.reward_address) == Some(&address) {
                let next_contrib = addresses
                    .pop()
                    .expect("BUG: first() returned some, but pop() is none.");
                let additional_amt = next_contrib.amount_stacked;

                if let Some(stacker) = next_contrib.stacker {
                    contributed_stackers.push((stacker.clone(), additional_amt));
                }

                stacked_amt = stacked_amt
                    .checked_add(additional_amt)
                    .expect("CORRUPTION: Stacker stacked > u128 max amount");
            }
```

**File:** stackslib/src/chainstate/stacks/boot/mod.rs (L1143-1177)
```rust
            // if stacker did not qualify for a slot *and* they have a stacker
            //   pointer set by the PoX contract, then add them to auto-unlock list
            if slots_taken == 0 && !contributed_stackers.is_empty() {
                info!(
                    "{}",
                    if epoch_id.supports_pox_missed_slot_unlocks() {
                        "Stacker missed reward slot, added to unlock list"
                    } else {
                        "Stacker missed reward slot"
                    };
                    "reward_address" => %address.clone().to_b58(),
                    "threshold" => threshold,
                    "stacked_amount" => stacked_amt
                );
                if !epoch_id.supports_pox_missed_slot_unlocks() {
                    continue;
                }
                contributed_stackers
                    .sort_by_cached_key(|(stacker, ..)| to_hex(&stacker.serialize_to_vec()));
                while let Some((contributor, amt)) = contributed_stackers.pop() {
                    let mut total_amount = amt;
                    while contributed_stackers.last().map(|(stacker, ..)| stacker)
                        == Some(&contributor)
                    {
                        let (add_stacker, additional) = contributed_stackers
                            .pop()
                            .expect("BUG: last() returned some, but pop() is none.");
                        assert_eq!(&add_stacker, &contributor);
                        total_amount = total_amount
                            .checked_add(additional)
                            .expect("CORRUPTION: Stacked stacked > u128 max amount");
                    }
                    missed_slots.push((contributor, total_amount));
                }
            }
```

**File:** stackslib/src/chainstate/stacks/boot/mod.rs (L1183-1191)
```rust
        RewardSet::V0(RewardSetV0 {
            rewarded_addresses: reward_set,
            start_cycle_state: PoxStartCycleInfo {
                missed_reward_slots: missed_slots,
            },
            signers: signer_set,
            pox_ustx_threshold: Some(threshold),
        })
    }
```
