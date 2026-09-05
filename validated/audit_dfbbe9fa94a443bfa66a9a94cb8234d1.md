[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L336-342)
```rust
/// One (signer_key, amount_ustx) pair contributing to a cycle's signer set,
/// as produced by walking pox-5's per-cycle signer-set linked list.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RawPox5Entry {
    pub(crate) amount_ustx: u128,
    pub(crate) signer_key: [u8; SIGNERS_PK_LEN],
}
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L424-447)
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

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L866-871)
```rust
        // This leaves some unassigned ("leftover") slots, which are handed out one-per-signer
        //  in descending fractional-remainder order (ties broken by pubkey-sort order).
        //
        // This avoids degenerate modes of the floor-and-drop scheme: when more than
        // `reward_slots` distinct signers hold roughly equal stake, every base weight floors to
        // 0, and without the leftover round the entire signer set could be dropped.
```

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

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L893-911)
```rust
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
