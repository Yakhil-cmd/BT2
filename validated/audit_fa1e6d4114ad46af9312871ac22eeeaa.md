#No Vulnerability found for this question.

The `From<StoredExtendedRewards> for generated::Rewards` and reverse conversions in `storage-proto/src/convert.rs` are pure identity-preserving mapping operations over a `Vec` — each element is converted 1:1 in order via `.into_iter().map(|r| r.into()).collect()`, with no filtering, grouping, or deduplication logic present or removed by this code. [1](#0-0) 

This means the conversion neither introduces duplicate entries nor is capable of "deduplicating" them — it simply transcodes whatever `Vec<StoredExtendedReward>` it is given (produced upstream by the reward-collection layer) into the equivalent protobuf-generated `Vec<generated::Reward>`, and vice versa, preserving order and cardinality exactly. `StoredExtendedRewards` itself is just a type alias for `Vec<StoredExtendedReward>` with no set-like or keyed-by-pubkey structure. [2](#0-1) 

The actual invariant "each stake account earns rewards for a given epoch exactly once" is a property of the reward calculation/distribution layer (e.g., `calculate_rewards_for_partitioning` and `update_reward_history_in_partition` in `runtime/src/bank/partitioned_epoch_rewards/`), not of this storage-proto transcoding layer. [3](#0-2) [4](#0-3) 

Since `convert.rs` performs no deduplication and adds/removes no entries, it cannot be the point at which duplicate rewards "survive" or "fail to survive" — it is a lossless, order-preserving transcoder. Any duplicate-reward concern would have to be proven against the reward-generation logic that produces the input `Vec<StoredExtendedReward>` in the first place (which computes rewards once per epoch from a stakes-cache snapshot, not per attacker-triggered instruction sequence), and no such flaw is demonstrated or locatable in this file. The described attacker flow (chaining split→deactivate→merge) does not have any established call path into `storage-proto/src/convert.rs`, and no evidence exists that reward calculation appends more than one `Reward` per pubkey per epoch. This question does not identify a concrete, reachable vulnerability in the cited conversion functions.

### Citations

**File:** storage-proto/src/convert.rs (L92-118)
```rust
impl From<StoredExtendedRewards> for generated::Rewards {
    fn from(rewards: StoredExtendedRewards) -> Self {
        Self {
            rewards: rewards
                .into_iter()
                .map(|r| {
                    let r: Reward = r.into();
                    r.into()
                })
                .collect(),
            num_partitions: None,
        }
    }
}

impl From<generated::Rewards> for StoredExtendedRewards {
    fn from(rewards: generated::Rewards) -> Self {
        rewards
            .rewards
            .into_iter()
            .map(|r| {
                let r: Reward = r.into();
                r.into()
            })
            .collect()
    }
}
```

**File:** storage-proto/src/lib.rs (L76-94)
```rust
pub type StoredExtendedRewards = Vec<StoredExtendedReward>;

#[derive(Serialize, Deserialize, SchemaRead, SchemaWrite)]
pub struct StoredExtendedReward {
    pubkey: String,
    lamports: i64,
    #[serde(deserialize_with = "default_on_eof")]
    #[wincode(with = "wincode_compat::DefaultOnEmptyRead<u64>")]
    post_balance: u64,
    #[serde(deserialize_with = "default_on_eof")]
    #[wincode(with = "wincode_compat::DefaultOnEmptyRead<Option<RewardType>>")]
    reward_type: Option<RewardType>,
    #[serde(deserialize_with = "default_on_eof")]
    #[wincode(with = "wincode_compat::DefaultOnEmptyRead<Option<u8>>")]
    commission: Option<u8>,
    #[serde(deserialize_with = "default_on_eof")]
    #[wincode(with = "wincode_compat::DefaultOnEmptyRead<Option<u16>>")]
    commission_bps: Option<u16>,
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L226-237)
```rust
    /// insert non-zero stake rewards to self.rewards
    /// Return the number of rewards inserted
    fn update_reward_history_in_partition(&self, stake_rewards: &[StakeReward]) -> usize {
        let mut rewards = self.rewards.write().unwrap();
        rewards.reserve(stake_rewards.len());
        let initial_len = rewards.len();
        stake_rewards
            .iter()
            .filter(|x| x.get_stake_reward() > 0)
            .for_each(|x| rewards.push((x.stake_pubkey, x.stake_reward_info.into())));
        rewards.len().saturating_sub(initial_len)
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L502-518)
```rust
        let CalculateValidatorRewardsResult {
            reward_commissions,
            stake_reward_calculation: stake_rewards,
            point_value,
        } = self
            .calculate_validator_rewards(
                stake_history,
                stake_delegations,
                cached_vote_accounts,
                rewarded_epoch,
                epoch_inflation_rewards,
                reward_epoch_delegated_stakes,
                reward_calc_tracer,
                thread_pool,
                metrics,
            )
            .unwrap_or_default();
```
