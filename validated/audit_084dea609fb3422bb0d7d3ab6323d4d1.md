### Title
Vote credit latency-to-reward calibration (`VOTE_CREDITS_GRACE_SLOTS`/`VOTE_CREDITS_MAXIMUM_PER_SLOT`) is not scaled to the active slot-time regime, causing misattributed epoch rewards - (File: `programs/vote/src/vote_state/handler.rs`)

### Summary
`VoteStateHandler::credits_for_vote_at_index` awards vote credits using a latency-to-credit curve keyed on two fixed, slot-count constants — `VOTE_CREDITS_GRACE_SLOTS` and `VOTE_CREDITS_MAXIMUM_PER_SLOT` [1](#0-0) . These constants were calibrated for the legacy 400ms slot duration, but Agave now supports multiple slot-time regimes (400/350/300/250/200ms) selected via feature-gated `SlotParams`, and every other timing-sensitive protocol constant (inflation rate, `slots_per_year`, cost-tracker limits, partitioned-reward budget, VAT burn amount, shred/entry-size limits) is explicitly re-derived per slot-time regime in `runtime/src/slot_params.rs` [2](#0-1) . The vote-credit latency thresholds are the one reward-relevant "rate per unit time" constant that is *not* included in that per-regime table, so they remain fixed in units of slots rather than wall-clock time — the exact bug class described in the referenced report (`borrowRateMaxMantissa` fixed per-block instead of scaled to actual block time).

### Finding Description
`compute_vote_latency` measures how many slots elapsed between the voted-for slot and the landing slot of that vote, capped at `u8::MAX` [3](#0-2) . That slot-count latency is then converted into a credit amount:
```
match latency.checked_sub(VOTE_CREDITS_GRACE_SLOTS) {
    None | Some(0) => VOTE_CREDITS_MAXIMUM_PER_SLOT as u64, // full credits
    Some(diff) => VOTE_CREDITS_MAXIMUM_PER_SLOT.checked_sub(diff) ... // degrades to 1
}
``` [4](#0-3) 

This formula implicitly assumes that "N slots of latency" corresponds to a fixed amount of real time — true only under the legacy 400ms slot. Once a slot-time reduction feature activates (e.g. `reduce_slot_time_to_200ms`), `ns_per_slot` is halved via `SlotParamsArchive`/`Bank::apply_slot_time_persistent_changes` [5](#0-4) , but `VOTE_CREDITS_GRACE_SLOTS`/`VOTE_CREDITS_MAXIMUM_PER_SLOT` are compile-time constants pulled straight from `solana_vote_interface::state` with no per-regime override, unlike every analogous timing constant that is deliberately re-tabulated for 350/300/250/200ms in `slot_params.rs`.

The consequence: the same real-world network/vote round-trip latency now corresponds to roughly twice as many slots once 200ms slots are active, pushing validators further down (or entirely off) the grace-slot/maximum-credit curve even though their actual physical voting performance is unchanged.

### Impact Explanation
Epoch inflation rewards are distributed proportionally to accumulated vote credits/points via `calculate_reward_points_partitioned`, which sums `credits_for_vote_at_index`-derived points per stake delegation and turns them into `PointValue` used for `epoch_inflation_rewards` distribution [6](#0-5) . Because the credit curve is denominated in slots rather than wall-clock time, activating a slot-time-reduction feature silently and systematically re-weights the reward split across the entire validator set — validators do not receive credits proportional to their real voting timeliness relative to peers, i.e., rewards become misattributed cluster-wide the moment a slot-time regime change takes effect, without any code path recalibrating the grace/maximum thresholds the way `slots_per_year`, cost limits, and other slot-time-dependent quantities are recalibrated.

### Likelihood Explanation
This is not a hypothetical: `reduce_slot_time_to_350ms/300ms/250ms/200ms` are real, already-defined feature gates with fully worked-out `SlotParams` tables and dedicated tests (`test_reduce_slot_time_features`, `test_reduce_slot_time_range_duration`) [7](#0-6) , showing slot-time reduction is an actively maintained migration path for this codebase. Every other timing-sensitive constant used for stake/reward accounting was deliberately given a per-regime table entry precisely because engineers recognized fixed slot-based constants break under variable slot time; the vote-credit thresholds were missed from that treatment, so the miscalibration triggers automatically and deterministically as soon as any of these already-shipped features activates on mainnet/testnet — no attacker action or config error is required.

### Recommendation
Add `vote_credits_grace_slots`/`vote_credits_maximum_per_slot` (or an equivalent wall-clock-denominated latency curve) to the `SlotParams` struct in `runtime/src/slot_params.rs`, populate per-regime values (`LEGACY_SLOT_PARAMS`, `SLOT_PARAMS_350MS`, `SLOT_PARAMS_300MS`, `SLOT_PARAMS_250MS`, `SLOT_PARAMS_200MS`) scaled to keep the grace/maximum window equivalent in real time, and thread the effective values into `credits_for_vote_at_index` (or convert `latency` into an `ns`-based value before applying the thresholds) instead of relying on the fixed `VOTE_CREDITS_GRACE_SLOTS`/`VOTE_CREDITS_MAXIMUM_PER_SLOT` constants from `solana_vote_interface::state`.

### Proof of Concept
1. Activate `feature_set::reduce_slot_time_to_200ms` (a real feature already tested in `runtime/src/bank/tests.rs`) so `ns_per_slot` becomes `200_000_000` per `SLOT_PARAMS_200MS` [8](#0-7) .
2. Two validators, A and B, have identical real-world vote-propagation latency (e.g., 400ms round trip). Under the legacy 400ms-slot regime this is ~1 slot of latency for both; under the 200ms regime it becomes ~2 slots of latency for both.
3. Because `credits_for_vote_at_index` subtracts `VOTE_CREDITS_GRACE_SLOTS` (fixed) from the slot-count latency and caps at `VOTE_CREDITS_MAXIMUM_PER_SLOT` (fixed) [4](#0-3) , both validators earn fewer credits per vote after the slot-time reduction takes effect, purely due to the constant not scaling — despite no change in real network performance.
4. This shift is applied identically to every validator in the cluster and flows directly into `calculate_reward_points_partitioned` → epoch inflation-reward distribution [9](#0-8) , changing the relative share of rewards captured by validators with different (but previously-equivalent) real-time latency profiles, i.e., misattributing inflation rewards across the validator/stake-delegator population as a direct side effect of an already-implemented slot-time-reduction feature activation.

### Citations

**File:** programs/vote/src/vote_state/handler.rs (L394-423)
```rust
    pub(crate) fn credits_for_vote_at_index(&self, index: usize) -> u64 {
        let latency = self
            .votes()
            .get(index)
            .map_or(0, |landed_vote| landed_vote.latency);

        // If latency is 0, this means that the Lockout was created and stored from a software version that did not
        // store vote latencies; in this case, 1 credit is awarded
        if latency == 0 {
            1
        } else {
            match latency.checked_sub(VOTE_CREDITS_GRACE_SLOTS) {
                None | Some(0) => {
                    // latency was <= VOTE_CREDITS_GRACE_SLOTS, so maximum credits are awarded
                    VOTE_CREDITS_MAXIMUM_PER_SLOT as u64
                }

                Some(diff) => {
                    // diff = latency - VOTE_CREDITS_GRACE_SLOTS, and diff > 0
                    // Subtract diff from VOTE_CREDITS_MAXIMUM_PER_SLOT which is the number of credits to award
                    match VOTE_CREDITS_MAXIMUM_PER_SLOT.checked_sub(diff) {
                        // If diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT, 1 credit is awarded
                        None | Some(0) => 1,

                        Some(credits) => credits as u64,
                    }
                }
            }
        }
    }
```

**File:** programs/vote/src/vote_state/handler.rs (L619-622)
```rust
// Computes the vote latency for vote on voted_for_slot where the vote itself landed in current_slot
pub(crate) fn compute_vote_latency(voted_for_slot: Slot, current_slot: Slot) -> u8 {
    std::cmp::min(current_slot.saturating_sub(voted_for_slot), u8::MAX as u64) as u8
}
```

**File:** runtime/src/slot_params.rs (L122-181)
```rust
pub const LEGACY_HASHES_PER_TICK: u64 = 62_500;
pub(crate) const LEGACY_SLOT_PARAMS: SlotParams = SlotParams {
    ns_per_slot: 400_000_000,
    slots_per_year: 78_892_314.984,
    hashes_per_tick: Some(LEGACY_HASHES_PER_TICK),
    cost_tracker_limits: CostTrackerLimits::new(24_000_000, 60_000_000, 100_000_000),
    max_data_shreds_per_slot: 32_768,
    max_code_shreds_per_slot: 32_768,
    max_entry_bytes_per_slot: 20 * 1024 * 1024,
    partitioned_epoch_rewards_stake_account_stores_per_block: 4096,
    vat_to_burn_per_epoch: 1_600_000_000,
};

pub(crate) const SLOT_PARAMS_350MS: SlotParams = SlotParams {
    ns_per_slot: 350_000_000,
    slots_per_year: 90_162_645.696,
    hashes_per_tick: Some(54_687),
    cost_tracker_limits: CostTrackerLimits::new(21_000_000, 52_500_000, 87_500_000),
    max_data_shreds_per_slot: 28_672,
    max_code_shreds_per_slot: 28_672,
    max_entry_bytes_per_slot: 18_350_080,
    partitioned_epoch_rewards_stake_account_stores_per_block: 3_584,
    vat_to_burn_per_epoch: 1_400_000_000,
};

pub(crate) const SLOT_PARAMS_300MS: SlotParams = SlotParams {
    ns_per_slot: 300_000_000,
    slots_per_year: 105_189_753.312,
    hashes_per_tick: Some(46_875),
    cost_tracker_limits: CostTrackerLimits::new(18_000_000, 45_000_000, 75_000_000),
    max_data_shreds_per_slot: 24_576,
    max_code_shreds_per_slot: 24_576,
    max_entry_bytes_per_slot: 15_728_640,
    partitioned_epoch_rewards_stake_account_stores_per_block: 3_072,
    vat_to_burn_per_epoch: 1_200_000_000,
};

pub(crate) const SLOT_PARAMS_250MS: SlotParams = SlotParams {
    ns_per_slot: 250_000_000,
    slots_per_year: 126_227_703.974,
    hashes_per_tick: Some(39_062),
    cost_tracker_limits: CostTrackerLimits::new(15_000_000, 37_500_000, 62_500_000),
    max_data_shreds_per_slot: 20_480,
    max_code_shreds_per_slot: 20_480,
    max_entry_bytes_per_slot: 13_107_200,
    partitioned_epoch_rewards_stake_account_stores_per_block: 2_560,
    vat_to_burn_per_epoch: 1_000_000_000,
};

pub(crate) const SLOT_PARAMS_200MS: SlotParams = SlotParams {
    ns_per_slot: 200_000_000,
    slots_per_year: 157_784_629.968,
    hashes_per_tick: Some(31_250),
    cost_tracker_limits: CostTrackerLimits::new(12_000_000, 30_000_000, 50_000_000),
    max_data_shreds_per_slot: 16_384,
    max_code_shreds_per_slot: 16_384,
    max_entry_bytes_per_slot: 10_485_760,
    partitioned_epoch_rewards_stake_account_stores_per_block: 2_048,
    vat_to_burn_per_epoch: 800_000_000,
};
```

**File:** runtime/src/bank.rs (L4888-4899)
```rust
    /// Applies slot-time changes for fields serialized into snapshots.
    fn apply_slot_time_persistent_changes(&mut self) {
        let params = self.current_slot_params();
        self.ns_per_slot = params.ns_per_slot();
        self.slots_per_year = params.slots_per_year();
        self.rent_collector.slots_per_year = params.slots_per_year();
        if !self.feature_set.is_active(&feature_set::alpenglow::id())
            && self.hashes_per_tick().is_some()
        {
            self.set_hashes_per_tick(params.hashes_per_tick());
        }
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L940-1008)
```rust
    /// Calculates epoch reward points from stake/vote accounts.
    /// Returns reward lamports and points for the epoch or none if points == 0.
    fn calculate_reward_points_partitioned<'a>(
        &self,
        stake_history: &StakeHistory,
        stake_delegations: &Vec<(&'a Pubkey, &'a StakeAccount<Delegation>)>,
        cached_vote_accounts: &CachedVoteAccounts<'_>,
        epoch_inflation_rewards: u64,
        ag_epoch_type: &AlpenglowEpochType,
        thread_pool: &ThreadPool,
        metrics: &RewardsMetrics,
    ) -> Option<PointValue> {
        let CachedVoteAccounts {
            distribution_epoch_vote_accounts,
            ..
        } = cached_vote_accounts;

        let solana_vote_program: Pubkey = solana_vote_program::id();
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        match ag_epoch_type {
            AlpenglowEpochType::Alpenglow { .. } => {
                // In alpenglow, we do not need to compute `PointValue::points` as the final
                // rewards are simply the total credits stored in the vote account.  We just need
                // to return a `Some` value with valid rewards.
                return Some(PointValue {
                    rewards: epoch_inflation_rewards,
                    points: 0,
                });
            }
            AlpenglowEpochType::Tower => {
                // For tower we need to compute the valid `PointValue::points`.
            }
            AlpenglowEpochType::MigrationEpoch { .. } => {
                // For the migrating epoch, we need to compute the tower portion of `PointValue::points`.
            }
        }

        let use_fixed_point_stake_math = self.use_fixed_point_stake_math();
        let (points, measure_us) = measure_us!(thread_pool.install(|| {
            stake_delegations
                .par_iter()
                .map(|(_stake_pubkey, stake_account)| {
                    let vote_pubkey = stake_account.delegation().voter_pubkey;

                    let Some(vote_account) = distribution_epoch_vote_accounts.get(&vote_pubkey)
                    else {
                        return 0;
                    };
                    if vote_account.owner() != &solana_vote_program {
                        return 0;
                    }

                    calculate_points_for_tower(
                        stake_account.stake_state(),
                        DelegatedVoteState::from(vote_account.vote_state_view()),
                        stake_history,
                        new_warmup_cooldown_rate_epoch,
                        use_fixed_point_stake_math,
                    )
                    .unwrap_or(0)
                })
                .sum::<u128>()
        }));
        metrics.calculate_points_us.fetch_add(measure_us, Relaxed);

        (points > 0).then_some(PointValue {
            rewards: epoch_inflation_rewards,
            points,
        })
```

**File:** runtime/src/bank/tests.rs (L6977-7055)
```rust
#[test]
fn test_reduce_slot_time_range_duration() {
    const SLOTS_PER_EPOCH: Slot = 32;
    let bank_for_activations = |activations: &[(Pubkey, Slot)]| {
        let (mut genesis_config, _) = create_genesis_config_with_legacy_hashes(1_000_000);
        genesis_config.epoch_schedule =
            EpochSchedule::custom(SLOTS_PER_EPOCH, SLOTS_PER_EPOCH, false);
        let mut bank = Bank::new_for_tests(&genesis_config);
        let mut feature_set = FeatureSet::default();
        for (feature_id, activation_slot) in activations {
            feature_set.activate(feature_id, *activation_slot);
        }
        bank.feature_set = Arc::new(feature_set);
        bank.refresh_slot_params();
        bank
    };

    let ordered_activations = slot_time_feature_gates()
        .into_iter()
        .zip([1, 33, 65, 97])
        .map(|((feature_id, _), activation_slot)| (feature_id, activation_slot))
        .collect::<Vec<_>>();
    let bank = bank_for_activations(&ordered_activations);

    let expected_duration = [
        (SLOTS_PER_EPOCH, LEGACY_SLOT_PARAMS),
        (SLOTS_PER_EPOCH, SLOT_PARAMS_350MS),
        (SLOTS_PER_EPOCH, SLOT_PARAMS_300MS),
        (SLOTS_PER_EPOCH, SLOT_PARAMS_250MS),
        (SLOTS_PER_EPOCH, SLOT_PARAMS_200MS),
    ]
    .into_iter()
    .map(|(slots, params)| slots as f64 / params.slots_per_year())
    .sum::<f64>();

    assert_eq!(
        bank.slot_range_duration_in_years(0, SLOTS_PER_EPOCH * 5)
            .to_bits(),
        expected_duration.to_bits()
    );
    assert_eq!(
        bank.slot_range_duration_nanos(0, SLOTS_PER_EPOCH * 5 - 1),
        [
            (SLOTS_PER_EPOCH, LEGACY_SLOT_PARAMS),
            (SLOTS_PER_EPOCH, SLOT_PARAMS_350MS),
            (SLOTS_PER_EPOCH, SLOT_PARAMS_300MS),
            (SLOTS_PER_EPOCH, SLOT_PARAMS_250MS),
            (SLOTS_PER_EPOCH, SLOT_PARAMS_200MS),
        ]
        .into_iter()
        .map(|(slots, params)| u128::from(slots) * params.ns_per_slot())
        .sum::<u128>()
    );

    let [reduce_to_350ms, _, _, reduce_to_200ms] = slot_time_feature_ids();
    let bank =
        bank_for_activations(&[(reduce_to_200ms, 1), (reduce_to_350ms, SLOTS_PER_EPOCH + 1)]);
    assert_eq!(
        bank.slot_params_at_slot(SLOTS_PER_EPOCH - 1),
        LEGACY_SLOT_PARAMS
    );
    assert_eq!(bank.slot_params_at_slot(SLOTS_PER_EPOCH), SLOT_PARAMS_200MS);
    assert_eq!(
        bank.slot_params_at_slot(SLOTS_PER_EPOCH * 2),
        SLOT_PARAMS_200MS
    );
    assert_eq!(
        bank.slot_range_duration_in_years(0, SLOTS_PER_EPOCH * 3)
            .to_bits(),
        (SLOTS_PER_EPOCH as f64 / LEGACY_SLOT_PARAMS.slots_per_year()
            + (SLOTS_PER_EPOCH * 2) as f64 / SLOT_PARAMS_200MS.slots_per_year())
        .to_bits()
    );
    assert_eq!(
        bank.slot_range_duration_nanos(0, SLOTS_PER_EPOCH * 3 - 1),
        u128::from(SLOTS_PER_EPOCH) * LEGACY_SLOT_PARAMS.ns_per_slot()
            + u128::from(SLOTS_PER_EPOCH * 2) * SLOT_PARAMS_200MS.ns_per_slot()
    );
}
```
