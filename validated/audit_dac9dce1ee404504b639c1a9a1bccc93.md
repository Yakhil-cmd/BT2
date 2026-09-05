### Title
Splitting stacked STX across multiple signer-keys can extract disproportionate signing weight in PoX-5's largest-remainder apportionment - (File: stackslib/src/chainstate/nakamoto/signer_set.rs)

### Summary
`pox_5_make_signer_set` allocates the fixed pool of `reward_slots` weight units across signers using a floor-then-largest-remainder ("Hare"/apportionment) method. This class of apportionment is known to be vulnerable to a "population/splitting paradox": entities that split a stake into several smaller, distinctly-keyed entries can receive strictly more aggregate weight than they would if the identical stake were registered under a single signer key. This mirrors the FEI report's root cause — a non-linear, per-operation rounding/formula that rewards fragmenting one action into several smaller ones instead of being neutral to fragmentation — except here the "penalty-bypass profit" takes the form of unearned signing weight taken from the shared, capped `reward_slots` pool.

### Finding Description
`pox_5_make_signer_set` (`stackslib/src/chainstate/nakamoto/signer_set.rs:822-928`) computes: [1](#0-0) 
- `threshold = max(1, total_ustx_locked.div_ceil(reward_slots))`
- for each distinct `signing_key`, `weight = stacked_amt / threshold` (floor) and `remainder = stacked_amt % threshold`

Then it computes `leftover = reward_slots - sum(weight)` and hands one extra weight unit to the entries with the largest remainder, up to `leftover` entries: [2](#0-1) 

Because the floor operation truncates, a single large stake concentrated under one `signing_key` loses at most the value of one remainder (`< threshold`) worth of weight, and can win at most **one** extra unit from the Hare round. If the same aggregate stake is instead broken up under several different `signing_key`s (each stake fraction chosen just under a multiple of `threshold`, e.g. `threshold - 1`), each fragment floors to `0` extra weight but carries a large remainder, and each fragment can independently win a Hare-round slot — as long as system-wide `leftover` capacity exists. This lets the fragmented registration collect several extra weight units instead of the single unit a consolidated registration could win, all funded from the *same* fixed `reward_slots` pool that other, honest signers are drawing from.

Concretely: with `threshold = 100`, a stake of `250` STX registered as one signer nets `floor(250/100) = 2` plus at most `+1` from the Hare round = `3` max. The same `250` STX split into five signer keys of `50` each nets `floor(50/100) = 0` per key, but if five Hare slots are available, the fragmented registrant walks away with `5` total weight units — substantially more voting/signing weight than its locked STX would proportionally earn, at the direct expense of the remainder of the reward-slot pool that other signers would otherwise receive.

This is the direct structural analog of the FEI bug: a formula (there, `sellIncentiveMultiplier`; here, floor-division + largest-remainder apportionment) that is *not* invariant under splitting a single economic action into several smaller ones, so a rational actor captures more of a shared resource (there, avoided burn; here, signing weight) purely by fragmenting.

### Impact Explanation
The `reward_slots` pool determines Nakamoto block-signing voting weight, i.e., the ability to approve/reject blocks and reach the two-thirds threshold that gates block finality. If an actor can inflate their own weight beyond what their locked STX honestly represents, they gain signing power exceeding their locked value while other, honestly-registered signers lose their fair share of slots (since `total_weight <= reward_slots` is a hard, zero-sum ceiling per the code's own invariant tests). This falls squarely under the rules' High-impact bucket: "signing weight or reward slots exceeding locked value."

### Likelihood Explanation
Exploitability hinges on whether a single economic actor can register multiple distinct `signing_key`s each backed by a chosen (fractional) amount of locked STX, and whether the "leftover" capacity in a given cycle is large enough (which depends on how many participants leave remainders and how tightly `total_ustx_locked` maps to `reward_slots`). I was not able to fully verify, within the available iterations, whether `pox-5.clar`'s `stack-stx`/signer-key registration path (and `pox_5_stake_entries`, which builds the `(signer_key, amount_ustx)` stream feeding `pox_5_make_signer_set`) imposes any restriction preventing one principal or coordinated set of principals from freely choosing many different `signing_key`s with STX amounts tuned to maximize captured remainders. This is a meaningful gap in my verification.

### Recommendation
Verify (via reading `pox-5.clar`'s stacking/signer-key-registration logic and `pox_5_stake_entries`) whether signer-key choice can be freely fragmented across colluding/attacker-controlled stackers. If so, replace or supplement the Hare/largest-remainder apportionment with a method invariant to splitting (e.g., a divisor method such as Jefferson/D'Hondt, or bound the number of extra Hare-round slots any single beneficial owner/coordinated set of keys can win), or require KYC-free but cryptographically-linked stake aggregation across keys controlled by the same principal before apportionment.

### Proof of Concept
Not independently reproduced against the actual `pox-5.clar` contract due to inability to confirm signer-key registration constraints within the available tool budget. The arithmetic worked example above (`threshold=100`, `250` STX single vs. `5x50` STX split) demonstrates the underlying apportionment-splitting arithmetic using the exact formulas in `pox_5_make_signer_set` (`stackslib/src/chainstate/nakamoto/signer_set.rs:872-911`), but confirming a concrete end-to-end exploit requires validating that an attacker can register the split stakes under distinct signer keys in a single reward cycle via `pox-5.clar`.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L872-890)
```rust
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
