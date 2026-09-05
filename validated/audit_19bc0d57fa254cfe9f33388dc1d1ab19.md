### Title
Bond-splitting across two signer keys can capture two largest-remainder leftover slots instead of one, inflating signing weight beyond the single-key entitlement - ([File: stackslib/src/chainstate/nakamoto/signer_set.rs])

### Summary
`NakamotoSigners::pox_5_make_signer_set` (the real home of the logic the question describes; the cited `signers_tests.rs` does not contain it) apportions `reward_slots` weight units to signer keys via floor-division plus a largest-remainder "leftover" round [1](#0-0) . Because the map is keyed by `signer_key` (`HashMap<[u8;33], u128>`, populated from `RawPox5Entry.signer_key`), a single stacker's locked uSTX registered under two distinct signer keys becomes two independent apportionment rows, each independently eligible for one leftover slot, whereas a single combined key is eligible for at most one leftover slot.

### Finding Description
The invariant that should hold is: `sum(weight assigned to attacker's keys) == floor(attacker's actually-locked ustx / threshold) + at most 1` (the "+1" being the single leftover slot a merged position could win). The code builds `signer_set: HashMap<[u8;33], u128>` by summing `amount_ustx` **per signer_key** [2](#0-1) , then computes `weight = stacked_amt / threshold` and `remainder = stacked_amt % threshold` per key, and hands one extra weight unit to each of the top-`leftover` remainders, ties broken by key ordering [1](#0-0) .

If an attacker locks amount `S` (via `stack-stx`/`delegate-stack-stx`/protocol-bond flows feeding `get-amount-delegated-for-signer`) and registers half under key A and half under key B such that `A%threshold` and `B%threshold` are individually large but `A%threshold + B%threshold < threshold` (no carry, i.e., `floor(A/threshold)+floor(B/threshold) == floor(S/threshold)`, so the base weight is unaffected), then in the leftover round both A and B can each win a leftover slot when `leftover >= 2` and other competitors have smaller remainders. That yields `weight_A + weight_B = floor(S/threshold) + 2`, exceeding the maximum any single merged key could ever obtain (`floor(S/threshold) + 1`). No check in `pox_5_make_signer_set`, `pox_5_stake_entries`, or `update_signers` deduplicates by owning principal or bond — the aggregation is strictly by `signer_key` [3](#0-2) [4](#0-3) , so nothing prevents one economic actor from fragmenting their delegated stake across multiple signer keys before the prepare-phase signer-set computation runs.

### Impact Explanation
The attacker gains one extra unit of signing weight / reward-slot allocation beyond what their actually-locked uSTX entitles them to under the largest-remainder scheme, matching the "signing weight or reward slots exceeding locked value" High-severity category. This inflates the attacker's voting power in `.signers` aggregate-key voting and their share of sBTC waterfall rewards distributed per weight, relative to honest single-key stackers, without locking additional STX. The gain is capped at +1 unit per attacker per cycle in the two-key case (more keys could in principle capture more leftover slots, up to `min(leftover, number_of_fragments)`, but each additional fragment must itself clear `SIGNER_SET_MIN_USTX` and win the remainder ranking against genuine competitors), and is repeatable every reward cycle as long as the leftover-slot/competitor conditions recur.

### Likelihood Explanation
This requires: (1) `leftover = reward_slots - assigned >= 2` for the cycle (leftover is bounded by the number of distinct participating signer entries, so it is more likely when the signer set is fragmented or thresholds are coarse relative to individual stakes); (2) the attacker's two fragment remainders must out-rank at least two other distinct-signer remainders in the tie-broken sort; (3) each fragment must independently clear `SIGNER_SET_MIN_USTX`. This is unprivileged and requires only splitting stacking/delegation calls across two self-controlled signer keys with amounts crafted to straddle the threshold's remainder distribution — computable off-chain by the attacker before submitting their stacking transactions in the same cycle, so it is fully feasible without any privileged role. It is not guaranteed to succeed every cycle (depends on other participants' remainder distribution), but is reproducible on demand by an attacker who models the current cycle's threshold and competing remainders before submitting their bond.

### Recommendation
Aggregate by the underlying stacker/bond principal (not solely by `signer_key`) before computing `weight`/`remainder`, or cap the number of leftover slots any single principal's aggregate stake can receive to 1, mirroring the invariant `weight <= floor(locked/threshold) + 1` per economic owner rather than per signer key.

### Proof of Concept
Extend `check_make_signer_set` in `stackslib/src/chainstate/nakamoto/tests/signer_set.rs`:
1. Construct a set of `RawPox5Entry` such that `reward_slots` and `total_ustx_locked` produce a `threshold` `T`, with several unrelated signer entries whose remainders are small (e.g. `T/10`).
2. Add two attacker entries with distinct `signer_key`s A and B where `amount_ustx_A = amount_ustx_B = k*T + T*0.4` for some integer `k`, chosen so `floor(A/T)+floor(B/T) == floor((A+B)/T)` (no carry) and each remainder (`0.4T`) beats the unrelated entries' remainders, with `leftover >= 2`.
3. Call `pox_5_make_signer_set` and assert `weight_A + weight_B == floor((A+B combined)/T) + 2`.
4. Separately call `pox_5_make_signer_set` with the same total amount under a single merged key and assert its maximum achievable weight is `floor((A+B)/T) + 1`.
5. Assert `weight_A + weight_B > merged_weight`, demonstrating the invariant `sum(weight) <= floor(locked/threshold) + 1` is violated.

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L339-342)
```rust
pub struct RawPox5Entry {
    pub(crate) amount_ustx: u128,
    pub(crate) signer_key: [u8; SIGNERS_PK_LEN],
}
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L421-453)
```rust
        let signer_key: [u8; SIGNERS_PK_LEN] =
            signer_key_buff.try_into().unwrap_or([0; SIGNERS_PK_LEN]);

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

        // Signers only enter the linked list after crossing SIGNER_SET_MIN_USTX,
        // so a zero here means contract state is inconsistent. Skip defensively.
        if amount_ustx == 0 {
            return Err(PoxEntryParsingError::Skip(format!(
                "signer {cur_signer} is in cycle linked list with zero delegated uSTX"
            )));
        }

        Ok(Some(RawPox5Entry {
            amount_ustx,
            signer_key,
        }))
    }
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L850-856)
```rust
            total_ustx_locked += entry.amount_ustx;

            signer_set
                .entry(entry.signer_key)
                .and_modify(|existing_entry| *existing_entry += entry.amount_ustx)
                .or_insert_with(|| entry.amount_ustx);
        }
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L882-911)
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
