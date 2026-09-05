### Title
Sock-puppet signer-key splitting can win extra Hamilton-apportionment leftover slots beyond a consolidated key's fair rounding - ([File: stackslib/src/chainstate/nakamoto/signer_set.rs])

### Summary
`NakamotoSigners::pox_5_make_signer_set` groups `RawPox5Entry` records by `signer_key` (a `HashMap<[u8;33], u128>`), computes a per-cycle `threshold = ceil(total_ustx_locked / reward_slots)`, and apportions weight via floor division plus a largest-remainder ("Hamilton") leftover round [1](#0-0) . Because the unit of apportionment is the `signer_key` rather than the underlying economic principal, an attacker who splits a fixed total stake across multiple distinct signer keys can win more leftover "+1" slots than a single consolidated key would ever be entitled to, since each split entry competes independently for the same shared leftover pool [2](#0-1) .

### Finding Description
The claimed equality — weight granted to one economic beneficiary should equal `beneficiary_locked_stx / threshold` rounded once — is not enforced anywhere in this code path. The per-signer apportionment logic is:

```
weight = stacked_amt / threshold   (floor)
remainder = stacked_amt % threshold
``` [3](#0-2) 

followed by sorting all entries by `remainder` descending (ties by `signing_key` ascending) and handing out `leftover = reward_slots - assigned` extra `+1`s to the top of that sorted list [4](#0-3) .

This is a per-entry Hamilton/largest-remainder apportionment. Hamilton's method individually satisfies the "quota rule" (`floor(quota) <= seats <= ceil(quota)`) for each entry, but that guarantee is per-entry, not per aggregated beneficiary. If a single principal splits total stake `X` into `k` separate `signer_key`s (e.g. via repeated `stack`/`register-signer` calls from rotated keys, as the comment in the code itself anticipates: *"when more than `reward_slots` distinct signers hold roughly equal stake, every base weight floors to 0... without the leftover round the entire signer set could be dropped"* [5](#0-4) ), each sub-entry can independently floor to 0 and carry a large `remainder` (up to `threshold-1`), and if the shared `leftover` pool has room, each sub-entry can independently win a `+1`. This lets the sum of weight for the split identity exceed `ceil(X/threshold)` — the true upper quota that a single consolidated key would ever get.

Concrete example: `threshold = 100`, attacker total stake `X = 150`. Consolidated: `weight = floor(150/100) = 1`, `remainder = 50`; even if it wins the leftover round, max attainable = 2 (= `ceil(150/100)`). Split into 3 keys of 50 uSTX each: each has `weight = floor(50/100) = 0`, `remainder = 50`; if the leftover pool (`reward_slots - sum-of-floors` across the whole cycle) has at least 3 free slots and these three tie-broken/ranked remainders beat competing entries, the attacker collects `0+1` three times = 3 total weight — one more slot than the true upper quota of 2 for the consolidated stake, purely by fragmenting one identity into three signer keys.

This is not prevented by any of the listed guards: `verify-not-prepare-phase`, `signer-manager-call-active` reentrancy guard, `check-pox-lock-period`, or `verify-signer-key-grant` all govern *when*/*how* a stacking call is accepted, not whether a single principal is prevented from registering multiple independent `signer_key`s and having them compete separately for the largest-remainder leftover round. The grouping in `pox_5_make_signer_set` is strictly by `signer_key` bytes [6](#0-5) ; there is no cross-reference back to the stacker/beneficiary principal at apportionment time, so no mechanism exists to cap or merge a single principal's multiple `signer_key` entries before the leftover round runs.

### Impact Explanation
The attacker gains signing weight (and hence reward-slot share and signing power in the Nakamoto signer set / `.signers` contract) beyond what their aggregate locked STX would earn under a single-key, fairly-rounded allocation. This dilutes honest signers' slice of `reward_slots`, matching the "signing weight or reward slots exceeding locked value" High-impact category. However, the magnitude of the gain is fundamentally bounded and small: it can add at most roughly one extra unit of `weight` per additional `signer_key` used to fragment the stake, and only insofar as the shared `leftover` pool (`reward_slots - Σfloor(stacked/threshold)` across *all* signers in the cycle, not just the attacker) has unused capacity and the attacker's fragment remainders outrank competing legitimate signers' remainders. It does not mint, unlock, or double-count any STX/sBTC value; it only skews the *relative distribution* of a fixed number of `reward_slots` weight units among registered signer keys. This is a genuine quota-rule violation inherent to per-key (rather than per-principal) largest-remainder apportionment, and it is repeatable every cycle in which the attacker re-registers fragmented `signer_key`s and the leftover pool has spare capacity.

### Likelihood Explanation
Feasibility depends on: (1) the attacker having a total stake sizeable enough, once fragmented, to still clear each `signer_key`'s independent registration floor and any per-signer minimum stacking amount (`SIGNER_SET_MIN_USTX`, enforced in `pox-5.clar`), (2) enough spare `leftover` capacity existing in that cycle (which is more likely precisely in the low-participation/many-small-signers regime the code's own comment describes), and (3) the attacker's crafted remainders out-ranking honest competitors' remainders/signing-key tie-breaks. All of these are plausible for a well-resourced but unprivileged attacker who controls many distinct signer keys and can time their `stack`/registration calls; no privileged role is required. The gain per cycle is capped at roughly one extra weight unit per extra fragment (bounded by `leftover`, itself bounded by the number of sub-threshold entries in the whole cycle), so while real, it is a marginal, incremental griefing/dilution vector rather than a large-scale one.

### Recommendation
Change the apportionment unit from `signer_key` to the underlying stacker/beneficiary principal (or otherwise cap/merge multiple `signer_key`s known to be controlled by, or registered on behalf of, the same principal) before running the largest-remainder leftover round in `pox_5_make_signer_set`, so the leftover `+1` competition happens per economic beneficiary rather than per signer key. Alternatively, replace the "one `+1` per top-remainder entry" leftover distribution with a scheme that verifiably respects the upper-quota bound (`weight <= ceil(aggregate_stake/threshold)`) per principal even when that principal registers multiple keys.

### Proof of Concept
Rust test (in `stackslib/src/chainstate/nakamoto/tests/signer_set.rs`, exercising `NakamotoSigners::pox_5_make_signer_set`):
1. Construct a fixed `reward_slots` (e.g. 4) and enough other `RawPox5Entry`s so `threshold` computes to a known value `T` (e.g. 100) via `total_ustx_locked.div_ceil(reward_slots)`.
2. Case A ("consolidated"): one `RawPox5Entry { signer_key: K1, amount_ustx: 150 }`.
3. Case B ("split"): three `RawPox5Entry`s each `{ signer_key: K1a/K1b/K1c, amount_ustx: 50 }` (same total 150 uSTX, same attacker), keeping all other entries identical between the two runs so `total_ustx_locked` and `threshold` are unchanged.
4. Run `pox_5_make_signer_set` for both cases.
5. Assert `sum(weight for signer_key in {K1a,K1b,K1c})` in Case B is `<= ceil(150 / T)` — i.e., assert it does **not** strictly exceed the weight granted to the single consolidated key `K1` in Case A. The test should demonstrate the current code violates this assertion (Case B totals 3 while Case A/ the true upper quota totals 2), confirming the quota-rule break.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L850-911)
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
