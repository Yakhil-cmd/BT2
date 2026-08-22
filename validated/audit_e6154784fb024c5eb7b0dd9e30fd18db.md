Based on the search, nearcore's validator reward mechanism is fundamentally different from the reward-per-token accumulator pattern described in the report.

The `SDLPoolPrimary` bug is a classic Synthetix-style staking rewards pool issue: an accumulator (`rewardPerToken`, `userRewardPerTokenPaid`) must be checkpointed via `updateReward()` any time a staked/effective balance changes, otherwise past-accrued rewards get miscounted against a newly enlarged balance, causing the pool's total claims to exceed actual reward token balance.

Nearcore's protocol-level reward mechanism works differently:
- `RewardCalculator::calculate_reward` in `chain/epoch-manager/src/reward_calculator.rs` recomputes the entire epoch's validator rewards fresh, once per epoch, directly from `total_supply`, `validator_stake`, and each validator's actual online/production stats at that specific point in time. [1](#0-0) 
- There is no persistent "reward-per-token" accumulator that stakers draw down from over time while an underlying weighted balance changes asynchronously; rewards are newly minted balance additions applied directly to validator stake via `update_validator_accounts` in `runtime/runtime/src/lib.rs`, using `account.set_locked(account.locked().checked_add(*reward)...)`. [2](#0-1) 
- Stake changes (proposals) affecting the next epoch's stake are applied only after rewards for the current epoch have already been calculated and attributed, via `apply_epoch_update_to_proposals`, so there's no scenario of an "incoming update" mutating a staked-balance accumulator mid-epoch without a reward checkpoint, because there is no such long-lived per-account accumulator to become stale.
<invoke name="grep_search">
<parameter name="query">userRewardPerTokenPaid|rewardPerToken|updateReward</parameter>
<parameter name="repo_name">hirayap/nearcore--003</parameter>
</invoke>

### Citations

**File:** chain/epoch-manager/src/reward_calculator.rs (L51-93)
```rust
    pub fn calculate_reward(
        &self,
        validator_block_chunk_stats: HashMap<AccountId, BlockChunkValidatorStats>,
        validator_stake: &HashMap<AccountId, Balance>,
        total_supply: Balance,
        _protocol_version: ProtocolVersion,
        epoch_duration: u64,
        online_thresholds: ValidatorOnlineThresholds,
        max_inflation_rate: Rational32,
    ) -> (HashMap<AccountId, Balance>, Balance) {
        let mut res = HashMap::new();
        let num_validators = validator_block_chunk_stats.len();
        let use_hardcoded_value = self.genesis_protocol_version == PROD_GENESIS_PROTOCOL_VERSION;
        let protocol_reward_rate = if use_hardcoded_value {
            Rational32::new_raw(1, 10)
        } else {
            self.protocol_reward_rate
        };
        let epoch_total_reward = Balance::from_yoctonear(
            (U256::from(*max_inflation_rate.numer() as u64)
                * U256::from(total_supply.as_yoctonear())
                * U256::from(epoch_duration)
                / (U256::from(self.num_seconds_per_year)
                    * U256::from(*max_inflation_rate.denom() as u64)
                    * U256::from(NUM_NS_IN_SECOND)))
            .as_u128(),
        );
        let epoch_protocol_treasury = Balance::from_yoctonear(
            (U256::from(epoch_total_reward.as_yoctonear())
                * U256::from(*protocol_reward_rate.numer() as u64)
                / U256::from(*protocol_reward_rate.denom() as u64))
            .as_u128(),
        );
        res.insert(self.protocol_treasury_account.clone(), epoch_protocol_treasury);
        if num_validators == 0 {
            return (res, Balance::ZERO);
        }
        let epoch_validator_reward =
            epoch_total_reward.checked_sub(epoch_protocol_treasury).unwrap();
        let mut epoch_actual_reward = epoch_protocol_treasury;
        let total_stake: Balance = validator_stake
            .values()
            .fold(Balance::ZERO, |sum, item| sum.checked_add(*item).unwrap());
```

**File:** runtime/runtime/src/lib.rs (L1591-1596)
```rust
                if let Some(reward) = validator_accounts_update.validator_rewards.get(account_id) {
                    tracing::debug!(target: "runtime", %account_id, %reward, locked = %account.locked(), "account adding reward to stake");
                    account.set_locked(account.locked().checked_add(*reward).ok_or_else(|| {
                        RuntimeError::UnexpectedIntegerOverflow("update_validator_accounts".into())
                    })?);
                }
```
