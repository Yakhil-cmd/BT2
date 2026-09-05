### Title
PoX-4 Signer-Set Weight Rounds to Zero, Silently Producing an Unsigned/Empty Signer Set Despite Locked STX - ([File: stackslib/src/chainstate/stacks/boot/mod.rs])

### Summary
`StacksChainState::make_signer_set` (used by the PoX-4 reward-cycle computation path) allocates signing weight to each signer with a plain floor division `stacked_amt / threshold`, dropping any signer whose result is `0`. Unlike the newer PoX-5 implementation, it performs no remainder/"largest-remainder" correction, so it is possible for every signer's weight to floor to zero even though real STX was locked and counted as `participation > 0`. The PoX-4 caller does not check for this degenerate outcome (unlike PoX-5's caller, which explicitly aborts), so an empty signer set can be silently written for a cycle in which stackers genuinely locked STX.

### Finding Description
`make_signer_set` computes per-signer weight as:
```rust
let weight = u32::try_from(stacked_amt / threshold)...
if weight == 0 { return None; }
``` [1](#0-0) 

This is precisely the "floor-and-drop scheme" that PoX-5's own signer-set allocator (`pox_5_make_signer_set`) was rewritten to fix, because it can zero out an entire signer set when several signers hold comparable stake relative to `reward_slots`: [2](#0-1) 

The regression test added for the PoX-5 fix documents the exact failure mode this analog reproduces for the older scheme still used by PoX-4: [3](#0-2) 

Crucially, `make_signer_set`/`make_reward_set` is still the code path used for PoX-4 reward-cycle/signer computation: [4](#0-3) 

And unlike the PoX-5 path, which explicitly guards against an empty resulting signer set: [5](#0-4) 

the PoX-4 path performs no such check — it simply substitutes an empty vector and proceeds: [6](#0-5) 

Because `make_reward_set`/`make_signer_set` is invoked on the raw, unfiltered `RawRewardSetEntry` list (grouped by signing key) before the per-address reward-set-slot filtering: [7](#0-6) 

a set of signers whose individually-qualifying stacked amounts floor to zero signing weight under the aggregate `threshold` produces `Some(vec![])` rather than `None`, so the empty/degenerate signer set is not distinguished from "correctly computed and just small," and `pox_4_compute_and_update_signers` writes it straight to the `.signers` contract with no error path.

This breaks the equality that "locked STX participation implies proportional signing weight/authorized stacking action": stackers who locked real STX (`participation > 0`) can end up authorizing zero signing weight for the reward cycle, i.e., an unsigned/unauthorized stacking outcome for funds that are, in fact, locked.

### Impact Explanation
This is a High-impact defect: locked STX for a PoX-4 reward cycle can produce a signer set with zero (or disproportionately low, non-conservation-guaranteed) total weight, meaning legitimately staked funds do not translate into the corresponding signing authority they are entitled to for that cycle — an unsigned stacking action / temporary freezing of the utility of staked funds (no block-signing capability derived from otherwise-valid, locked stake) until the next cycle's set is recomputed.

### Likelihood Explanation
This requires only an unprivileged combination of several stackers/signers holding roughly comparable amounts relative to `reward_slots` and the computed `threshold` for a PoX-4 cycle — no admin or privileged action is needed, matching exactly the scenario the project's own regression test (`equal_stakes_exceeding_reward_slots_are_not_all_zeroed`) was written to demonstrate and fix, but only for the PoX-5 path.

### Recommendation
Port the same largest-remainder ("Hare quota") allocation and the "signer set became empty despite nonzero participation" guard from `pox_5_make_signer_set` / `pox_5_compute_and_update_signers` into `StacksChainState::make_signer_set` and `pox_4_compute_and_update_signers`, so PoX-4 reward-cycle signer weight allocation cannot degrade to an unauthorized-but-locked outcome.

### Proof of Concept
1. Configure a PoX-4 reward cycle with `reward_slots = N` and register more than `N` distinct signing keys, each individually stacking just enough to pass `get-stacking-minimum`/`can-stack-stx`, but with amounts such that `get_reward_threshold_and_participation`'s resulting `threshold` makes each signer's aggregate `stacked_amt / threshold` floor to `0` (achievable by having `threshold` computed slightly above each individual signer's share, analogous to the equal-stake construction in `equal_stakes_exceeding_reward_slots_are_not_all_zeroed`).
2. Call `StacksChainState::make_reward_set` → `make_signer_set` for that cycle as `pox_4_compute_and_update_signers` does.
3. Observe `signer_set` is `Some(vec![])` despite `participation > 0`; unlike the PoX-5 path, no error is raised, and the empty signer set is written to `.signers` for that reward cycle. [8](#0-7) [4](#0-3)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/mod.rs (L1020-1072)
```rust
    pub fn make_signer_set(
        threshold: u128,
        entries: &[RawRewardSetEntry],
    ) -> Option<Vec<NakamotoSignerEntry>> {
        let Some(first_entry) = entries.first() else {
            // entries is empty: there's no signer set
            return None;
        };
        // signing keys must be all-or-nothing in the reward set
        let expects_signing_keys = first_entry.signer.is_some();
        for entry in entries.iter() {
            if entry.signer.is_some() != expects_signing_keys {
                panic!("FATAL: stacking-set contains mismatched entries with and without signing keys.");
            }
        }
        if !expects_signing_keys {
            return None;
        }

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

        // finally, we must sort the signer set: the signer participation bit vector depends
        //  on a consensus-critical ordering of the signer set.
        signer_set.sort_by_key(|entry| entry.signing_key);

        Some(signer_set)
    }
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L703-738)
```rust
    fn pox_4_compute_and_update_signers(
        clarity: &mut ClarityTransactionConnection,
        pox_constants: &PoxConstants,
        reward_cycle: u64,
        pox_contract: &str,
        coinbase_height: u64,
    ) -> Result<SignerCalculation, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        let liquid_ustx = clarity.with_clarity_db_readonly(|db| db.get_total_liquid_ustx())?;
        let reward_slots = Self::get_pox_4_reward_slots(clarity, reward_cycle, pox_contract)?;
        let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
            pox_constants,
            &reward_slots[..],
            liquid_ustx,
        );

        let reward_set =
            StacksChainState::make_reward_set(threshold, reward_slots, StacksEpochId::Epoch30);

        test_debug!("Reward set for cycle {}: {:?}", &reward_cycle, &reward_set);

        let empty_signers = vec![];
        let events = Self::update_signers(
            clarity,
            reward_cycle,
            reward_set.signers().unwrap_or(&empty_signers),
            signers_contract,
            participation > 0,
            coinbase_height,
            is_mainnet,
        )?;

        Ok(SignerCalculation { events, reward_set })
    }
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L744-766)
```rust
    fn pox_5_compute_and_update_signers(
        clarity: &mut ClarityTransactionConnection,
        pox_constants: &PoxConstants,
        reward_cycle: u64,
        pox_contract: &str,
        coinbase_height: u64,
        _current_calculation_btc_height: u32,
        _current_epoch: &StacksEpochId,
    ) -> Result<SignerCalculation, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        // Build the `(signer_key, amount_ustx)` pair stream
        let mut entries = Self::pox_5_stake_entries(clarity, reward_cycle, pox_contract)?;
        let Pox5SignerSetOutput {
            signer_set,
            pox_ustx_threshold,
        } = Self::pox_5_make_signer_set(&mut entries, pox_constants)?;

        if signer_set.is_empty() {
            error!("Fatal network condition: reward set computed with an empty signer set. Cannot continue producing blocks");
            return Err(ChainstateError::PoxNoRewardCycle);
        }
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L858-911)
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

**File:** stackslib/src/chainstate/nakamoto/tests/signer_set.rs (L294-335)
```rust
#[test]
fn equal_stakes_exceeding_reward_slots_are_not_all_zeroed() {
    // Regression: more distinct signers than reward_slots, all with equal stake.
    //
    // The old floor-and-drop scheme set threshold = ceil(N*S / R) > S, so every
    // signer's weight floored to 0 and the entire set was dropped -- stalling the
    // chain. The Hare round must instead award one slot each to the top `R` signers
    // (by remainder, then signing_key), dropping only the surplus signers.
    let pox_constants = test_pox_constants(1); // reward_slots() == 4
    let reward_slots = pox_constants.reward_slots();
    assert_eq!(reward_slots, 4);
    let stake = 1_000_000u128;
    // 5 signers, only 4 slots.
    let entries: Vec<_> = (0..5u8)
        .map(|i| RawPox5Entry {
            signer_key: signer_key(i),
            amount_ustx: stake,
        })
        .collect();
    let mut iter = entries.into_iter().map(Ok);
    let Pox5SignerSetOutput { signer_set, .. } =
        NakamotoSigners::pox_5_make_signer_set(&mut iter, &pox_constants).expect("ok");

    assert_eq!(
        signer_set.len(),
        reward_slots as usize,
        "expected exactly reward_slots signers, not an empty/zeroed set"
    );
    for entry in &signer_set {
        assert_eq!(
            entry.weight, 1,
            "each surviving signer should hold one slot"
        );
    }
    let total_weight: u128 = signer_set.iter().map(|e| u128::from(e.weight)).sum();
    assert_eq!(total_weight, u128::from(reward_slots));
    // Ties broken by signing_key ascending: keys 0x00..0x03 win, 0x04 is dropped.
    assert!(
        !signer_set.iter().any(|e| e.signing_key == signer_key(0x04)),
        "highest-key signer should be the one dropped on tie-break"
    );
}
```
