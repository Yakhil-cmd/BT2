### Title
Block-reward lamports distributed via `store_stake_accounts_in_partition` are never pre-funded in the `EpochRewards` sysvar, causing a value-conservation break / validator panic - ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs, runtime/src/bank/partitioned_epoch_rewards/distribution.rs, runtime/src/bank/partitioned_epoch_rewards/sysvar.rs])

### Summary
`begin_partitioned_rewards` always calls `create_epoch_rewards_sysvar` with a hardcoded `block_rewards = 0`, regardless of whether `block_revenue_sharing` is active or how much block reward `calculate_block_reward` actually computed for the epoch's stake delegations. When `distribute_epoch_rewards_in_partition` later distributes a nonzero `block_reward_lamports_distributed`/`block_reward_lamports_burned`, `update_epoch_rewards_sysvar` tries to debit that amount from a sysvar account balance that was never credited with it, either panicking the validator or (depending on ordering/underflow semantics) leaving `bank.capitalization()` inconsistent with the lamports actually minted into stake accounts.

### Finding Description
`calculate_block_reward` (calculation.rs:174-232) computes a nonzero `block_reward` per stake delegation from the delegated vote account's `pending_delegator_rewards()`, gated only by `block_revenue_sharing` being active and `total_active_stake > 0`. [1](#0-0) 

In `calculate_stake_rewards_and_commissions`, the `(_, None)` match arm explicitly creates a `PartitionedStakeReward` carrying this nonzero `block_reward`, while pushing a `RewardAccumulation{ stake_reward: 0, commission: None }` — i.e. the block reward is *not* folded into `total_stake_rewards_lamports` or any commission bucket, it exists solely inside `PartitionedStakeReward.block_reward`. [2](#0-1) 

Later, `store_stake_accounts_in_partition` sums these into `block_reward_lamports_distributed`/`block_reward_lamports_burned`, and `build_updated_stake_reward` actually mints the lamports into the stake account via `checked_add_lamports(partitioned_stake_reward.block_reward)`. [3](#0-2) [4](#0-3) 

`distribute_epoch_rewards_in_partition` forwards `block_reward_lamports_distributed + block_reward_lamports_burned` into `update_epoch_rewards_sysvar` as the amount to debit from the sysvar's lamport balance: [5](#0-4) 

`update_epoch_rewards_sysvar` then performs `account.checked_sub_lamports(debit_block_reward_lamports).expect("epoch reward sysvar has enough lamports for distribution")`, assuming the sysvar was pre-funded with exactly the total block reward amount at creation time. [6](#0-5) 

However, the only production call site that creates the sysvar, `begin_partitioned_rewards`, hardcodes the `block_rewards` parameter to `0` — it never sums `PartitionedStakeReward.block_reward` across `rewards_calculation.stake_rewards` and passes it to `create_epoch_rewards_sysvar`: [7](#0-6) 

whereas `create_epoch_rewards_sysvar` itself expects a real `block_rewards` value and adds it to the sysvar account's lamports so it can later be debited without affecting capitalization: [8](#0-7) 

Because the sysvar is always created with `block_rewards = 0` in the real code path (only unit tests in `distribution.rs` manually invoke `create_epoch_rewards_sysvar` with a correct nonzero `block_rewards`), any epoch where `block_revenue_sharing` is active and at least one delegated vote account has `pending_delegator_rewards() > 0` will produce `block_reward_lamports_distributed > 0` with no matching sysvar pre-funding. Also, capitalization is only incremented by `stake_reward_lamports_minted`, never by `block_reward_lamports_distributed`, even though `build_updated_stake_reward` unconditionally mints `block_reward` lamports into the stake account: [9](#0-8) 

### Impact Explanation
This is a value-conservation violation: `store_stake_accounts_in_partition` mints `block_reward_lamports_distributed` lamports into stake accounts (increasing actual on-chain SOL) while `bank.capitalization()` is never adjusted for that amount, and the `EpochRewards` sysvar was never pre-funded to cover the corresponding debit. Depending on exact numeric conditions this manifests as either (a) a hard panic/validator halt at `update_epoch_rewards_sysvar`'s `.expect("epoch reward sysvar has enough lamports for distribution")`, or (b) silent capitalization under-reporting relative to actual minted lamports — both scoped-impact categories explicitly accepted (epoch-boundary halt, corrupted capitalization / illegitimate lamport minting).

### Likelihood Explanation
Preconditions are low-privilege and plausible once the `block_revenue_sharing` feature is active: an unprivileged vote-account owner only needs any nonzero `pending_delegator_rewards` on their vote account (e.g. via the vote program's `DepositDelegatorRewards` instruction visible in `vote_processor.rs`) and a delegated stake, which is normal validator operation, not a special attack. This means the mismatch is not attacker-specific brinkmanship of the `(0, None)` vs `(_, Some(res))` classification as hypothesized in the question, but a structural bug in `begin_partitioned_rewards` that would trigger deterministically and repeatably for essentially any epoch with active block revenue sharing and any nonzero pending delegator rewards.

### Recommendation
In `begin_partitioned_rewards`, compute the true total block reward for the epoch (sum of `PartitionedStakeReward.block_reward` across `rewards_calculation.stake_rewards.stake_rewards`) and pass that value — not a hardcoded `0` — into `create_epoch_rewards_sysvar`. Additionally, ensure `distribute_epoch_rewards_in_partition` increments capitalization by `block_reward_lamports_distributed` consistently with the sysvar's accounting model (or clarify/enforce that block-reward lamports are transferred out of an already-capitalized source, e.g. debited from the relevant vote account's `pending_delegator_rewards`/lamports at calculation time, matching the "block reward lamports already existed" invariant assumed by `create_epoch_rewards_sysvar`/`update_epoch_rewards_sysvar`).

### Proof of Concept
```rust
// runtime/src/bank/partitioned_epoch_rewards/calculation.rs (test module)
#[test]
fn test_begin_partitioned_rewards_ignores_block_reward_total() {
    // Setup: activate block_revenue_sharing, create a bank with one validator
    // whose vote account has pending_delegator_rewards > 0 and a delegated
    // stake account with e.g. zero epoch credits (so inflation stake_reward == 0,
    // matching the `(_, None)` arm).
    //
    // 1. Run through calculate_rewards()/calculate_validator_rewards() to obtain
    //    a PartitionedRewardsCalculation whose stake_rewards contain at least one
    //    PartitionedStakeReward with `block_reward > 0`.
    // 2. Call begin_partitioned_rewards(...) and inspect the created
    //    EpochRewards sysvar account's lamports.
    //
    // Expected (bug): sysvar lamports == rent-exempt minimum only
    //   (i.e. `block_rewards` component == 0), even though
    //   sum(stake_rewards.iter().map(|r| r.block_reward)) > 0.
    //
    // 3. Continue to distribute_epoch_rewards_in_partition for that partition.
    //    Expected (bug): panic at
    //    `account.checked_sub_lamports(debit_block_reward_lamports).expect(...)`
    //    OR (if made non-panicking) capitalization delta after distribution
    //    does not include block_reward_lamports_distributed, violating
    //    VALUE_CONSERVATION between minted stake-account lamports and
    //    capitalization/sysvar bookkeeping.
    //
    // Assertion:
    // assert_eq!(pre_epoch_rewards_account.lamports() - rent_exempt_minimum, expected_total_block_rewards);
    // (this currently fails because begin_partitioned_rewards hardcodes 0)
}
```

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L211-231)
```rust
    if total_active_stake == 0 {
        0
    } else {
        let stake = delegation_effective_stake(
            delegation,
            rewarded_epoch,
            stake_history,
            new_warmup_cooldown_rate_epoch,
            use_fixed_point_stake_math,
        );
        // During recalculation, if stake account has already received rewards,
        // it's possible to have `stake > total_active_stake`. If
        // `pending_delegator_rewards` is a huge number, we could potentially
        // overflow a `u64`. We can also have individual rewards look greater
        // than the pending rewards. This is harmless in practice, but we
        // clamp it just to be safe
        (pending_delegator_rewards as u128 * stake as u128 / total_active_stake as u128)
            .try_into()
            .unwrap_or(u64::MAX)
            .min(pending_delegator_rewards)
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L276-282)
```rust
        self.create_epoch_rewards_sysvar(
            distributed_lamports + distributed_to_incinerator_lamports + burned_lamports,
            distribution_starting_block_height,
            num_partitions,
            point_value,
            0, // block_rewards
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L851-892)
```rust
                    let (reward, maybe_reward_record) = match (block_reward, maybe_reward_record) {
                        (0, None) => (None, None),
                        (_, Some(res)) => {
                            let InflationRewardWithCommission {
                                inflation,
                                commission_pubkey,
                                reward_commission,
                            } = res;
                            let stake_reward = inflation.stake_reward;
                            (
                                Some(PartitionedStakeReward {
                                    stake_pubkey: **stake_pubkey,
                                    inflation,
                                    block_reward,
                                }),
                                Some(RewardAccumulation {
                                    stake_reward,
                                    commission: Some((commission_pubkey, reward_commission)),
                                }),
                            )
                        }
                        (_, None) => {
                            // Create a zero entry for distribution
                            let stake = *stake_account.stake();
                            let stake_reward = 0;
                            (
                                Some(PartitionedStakeReward {
                                    stake_pubkey: **stake_pubkey,
                                    inflation: InflationReward {
                                        stake,
                                        stake_reward,
                                        commission_bps: None,
                                    },
                                    block_reward,
                                }),
                                // Need a reward record for accumulator
                                Some(RewardAccumulation {
                                    stake_reward,
                                    commission: None,
                                }),
                            )
                        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L192-204)
```rust
        // increase total capitalization by the distributed rewards
        self.capitalization
            .fetch_add(stake_reward_lamports_minted, Relaxed);

        // decrease total capitalization by burned block rewards
        self.capitalization
            .fetch_sub(block_reward_lamports_burned, Relaxed);

        // decrease distributed capital from epoch rewards sysvar
        self.update_epoch_rewards_sysvar(
            stake_reward_lamports_minted + stake_reward_lamports_burned,
            block_reward_lamports_distributed + block_reward_lamports_burned,
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L262-267)
```rust
        account
            .checked_add_lamports(partitioned_stake_reward.inflation.stake_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
        account
            .checked_add_lamports(partitioned_stake_reward.block_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L393-407)
```rust
            ) {
                Ok(stake_reward) => {
                    stake_reward_lamports_minted += stake_reward_amount;
                    block_reward_lamports_distributed += block_reward_amount;
                    updated_stake_rewards.push(stake_reward);
                }
                Err(err) => {
                    error!(
                        "bank::distribution::store_stake_accounts_in_partition() failed for \
                         {stake_pubkey}, {stake_reward_amount} lamports burned: {err:?}"
                    );
                    stake_reward_lamports_burned += stake_reward_amount;
                    block_reward_lamports_burned += block_reward_amount;
                }
            }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/sysvar.rs (L58-69)
```rust
        // Now add the lamports separately without updating capitalization,
        // since block reward lamports already existed
        let mut account = self
            .get_account_with_fixed_root(&sysvar::epoch_rewards::id())
            .expect("created sysvar account exists");

        // SAFETY: block rewards come from existing lamports, which cannot
        // overflow
        account
            .checked_add_lamports(block_rewards)
            .expect("block rewards and sysvar account rent exemption must fit in a u64");
        self.store_account(&sysvar::epoch_rewards::id(), &account);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/sysvar.rs (L92-105)
```rust
        // Debit the lamports separately without updating capitalization,
        // since block reward lamports already existed
        let mut account = self
            .get_account_with_fixed_root(&sysvar::epoch_rewards::id())
            .expect("created sysvar account exists");

        // SAFETY: programmer error if we debit too many block rewards
        account
            .checked_sub_lamports(debit_block_reward_lamports)
            .expect("epoch reward sysvar has enough lamports for distribution");
        assert!(
            account.lamports() >= self.get_minimum_balance_for_rent_exemption(account.data().len()),
            "Sysvar account must have enough for rent exemption after debiting block rewards"
        );
```
