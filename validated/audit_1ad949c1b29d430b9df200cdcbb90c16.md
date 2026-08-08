I have enough context to write up the finding now.

### Title
Malicious front-run of a validator's designated commission collector burns that validator's staking commission when the collector account is later converted into a self-collecting vote account - ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
Under SIMD-0232 (`custom_commission_collector`), a vote account can designate any system-owned, rent-exempt account as its `inflation_rewards_collector`/`block_revenue_collector`. If a third party subsequently converts that same address into a vote account and designates itself as its own collector before the reward-distribution phase completes, the merging logic in `accumulate_lamports` deterministically **burns** the original vote account's entire commission for that epoch instead of paying it out. This is functionally the same bug class as the CCTP "malicious blacklisting of `mintRecipient` while a message is in-flight" report: a value that a legitimate party designates as a valid payment destination is externally mutated into an invalid one after the fact, during a window where the payment can no longer be redirected, causing an irrecoverable loss of funds for the honest party.

### Finding Description
Reward calculation happens in a "calculation" phase and is paid out several blocks later in a separate "distribution" phase (`distribute_partitioned_epoch_rewards`), so there is an in-flight window between when a commission recipient is computed and when it is actually credited [1](#0-0) .

During calculation, each stake account's commission is attributed to the vote account's chosen `commission_pubkey`, and an `is_vote_account` flag records only whether that commission_pubkey equals the *paying* vote account's own pubkey (self-collection), not whether the target address is generally a vote account [2](#0-1) .

These per-commission_pubkey entries from many different vote accounts are merged into a single `reward_commissions` map keyed by `commission_pubkey` via `RewardsAccumulator::add_reward`, which calls `accumulate_lamports` whenever two vote accounts happen to route to the same collector address [3](#0-2) .

`accumulate_lamports` documents and implements the exact scenario: vote account A validly designates system-owned account B as its collector; before rewards are paid out, B is allocated and initialized as its own vote account that self-collects (making `is_vote_account = true` for B's own entry). When A's `(false, is_vote_account=false)` entry is merged into B's `(true, is_vote_account=true)` entry, the code takes the `(false, true)` branch and burns the entirety of A's commission lamports (`dst.burned_lamports += src.commission_lamports`), rather than crediting them to the collector address [4](#0-3) .

At collector-address selection time, `NewCommissionCollector::validate_and_resolve_key` only checks that the address is *currently* system-owned, rent-exempt, and not reserved β€” it cannot guarantee the address will remain system-owned once distribution actually runs [5](#0-4) . There is no mechanism analogous to CCTP's `replaceMessage` to let vote account A redirect its already-calculated commission once its chosen collector account state changes underneath it, and once burned, the lamports are gone (capitalization is decremented, no recovery path exists) [6](#0-5) .

### Impact Explanation
An attacker can pre-fund and hold in reserve a large set of system-owned, rent-exempt "bait" pubkeys, wait for validators to legitimately designate one of them as a custom commission collector (e.g., because the address is advertised for delegator revenue sharing), and then, once the address is selected but before the vote account's commission for the current epoch is distributed, initialize that address as a self-collecting vote account. This deterministically causes 100% of the targeted validator's staking commission for the affected epoch to be burned rather than paid, with no way for the victim to intervene once the reward calculation has locked in the collector address. This is a concrete loss-of-funds bug (burned lamports), matching the reward-misattribution/loss bug class.

### Likelihood Explanation
Exploitation requires only unprivileged, permissionless actions available to any user: (1) create and fund a system-owned account, (2) wait for a validator to designate it via the vote program's `UpdateCommissionCollector` instruction (a legitimate, expected use case for shared/omnibus collector addresses), and (3) submit a `VoteInit`/initialize instruction converting that same address into a self-collecting vote account before the next reward distribution boundary. The race window spans the entire period between the calculation block and the corresponding distribution block, which is on the order of the number of reward partitions, giving ample time. No validator or privileged role is required.

### Recommendation
When accumulating reward commissions, do not rely solely on `is_vote_account` computed from the *paying* vote account's perspective. Instead, re-validate at distribution time (as is already partially done via `collector_type_checked` for non-vote collectors) whether the recipient address is currently a vote account distinct from the assigning vote account, and treat such a late transition as an invalid collector for the assigning entry consistently (e.g., always burn only the newly-invalidated portion, never silently let a colliding/attacker-controlled vote account's self-collection silently swallow another validator's commission) or, better, snapshot/lock the collector account's owner at calculation time and re-check it unchanged at distribution time, refusing distribution (and reverting to the safe default of the vote account itself) rather than burning when the underlying account type changed.

### Proof of Concept
1. Attacker creates account B, funds it as a rent-exempt system-owned account.
2. Validator/vote account A calls `UpdateCommissionCollector` designating B as its `inflation_rewards_collector`; passes validation in `NewCommissionCollector::validate_and_resolve_key` since B is currently system-owned and rent-exempt.
3. Epoch boundary occurs; reward calculation phase runs, producing a `RewardCommission` entry for A with `commission_pubkey = B`, `is_vote_account = false` (per `redeem_delegation_rewards`).
4. Before the distribution phase for that partition executes, attacker initializes B as its own vote account (`VoteInit`) and designates B as its own `inflation_rewards_collector` (self-collection), or B was already a self-collecting vote account waiting to be picked.
5. If B also earns any commission this epoch (or simply already exists as a self-collecting vote account entry in `reward_commissions`), `RewardsAccumulator::add_reward`/`accumulate_into_larger` merges A's entry into B's via `accumulate_lamports`, hitting the `(false, true)` branch and burning A's entire commission lamports instead of crediting B.
6. A's validator commission for the epoch is permanently lost with no mechanism to recover or redirect it, mirroring the CCTP `mintRecipient` blacklisting scenario.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L79-94)
```rust
    /// Process reward distribution for the block if it is inside reward interval.
    pub(in crate::bank) fn distribute_partitioned_epoch_rewards(&mut self) {
        let EpochRewardStatus::Active(status) = &self.epoch_reward_status else {
            return;
        };

        let distribution_starting_block_height = match &status {
            EpochRewardPhase::Calculation(status) => status.distribution_starting_block_height,
            EpochRewardPhase::Distribution(status) => status.distribution_starting_block_height,
        };

        let height = self.block_height();
        if height < distribution_starting_block_height {
            return;
        }

```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L92-104)
```rust
fn accumulate_lamports(src: &RewardCommission, dst: &mut RewardCommission) {
    match (src.is_vote_account, dst.is_vote_account) {
        (false, true) => {
            // Don't accumulate, burn everything in the source
            // reward commission entry.
            //
            // NOTE: There shouldn't be any burned lamports in the
            // source entry, but we're defensive
            dst.burned_lamports = dst
                .burned_lamports
                .saturating_add(src.commission_lamports)
                .saturating_add(src.burned_lamports);
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L128-141)
```rust
impl RewardsAccumulator {
    fn add_reward(&mut self, reward: RewardAccumulation) {
        self.num_stake_rewards = self.num_stake_rewards.saturating_add(1);
        self.total_stake_rewards_lamports = self
            .total_stake_rewards_lamports
            .saturating_add(reward.stake_reward);
        if let Some((commission_pubkey, reward_commission)) = reward.commission {
            self.reward_commissions
                .entry(commission_pubkey)
                .and_modify(|dst_reward_commission| {
                    accumulate_lamports(&reward_commission, dst_reward_commission);
                })
                .or_insert(reward_commission);
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L384-408)
```rust
        let RewardCommissionLamportAmounts {
            distributed_lamports,
            distributed_to_incinerator_lamports,
            burned_lamports,
        } = reward_commission_accounts.amounts;
        self.store_commission_accounts_partitioned(&reward_commission_accounts, rewards_metrics);
        self.update_reward_commissions(&reward_commission_accounts);

        let StakeRewardCalculation {
            total_stake_rewards_lamports,
            ..
        } = stake_rewards;

        // verify that we didn't pay any more than we expected to
        assert!(
            point_value.rewards
                >= distributed_lamports
                    + distributed_to_incinerator_lamports
                    + burned_lamports
                    + total_stake_rewards_lamports,
            "point_value={point_value:?}, distributed_lamports={distributed_lamports}, \
             distributed_to_incinerator_lamports={distributed_to_incinerator_lamports} \
             burned_lamports={burned_lamports}, \
             total_stake_rewards_lamports={total_stake_rewards_lamports}"
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L750-763)
```rust
                let (commission_pubkey, is_vote_account) = if custom_commission_collector {
                    let commission_pubkey = *vote_state
                        .inflation_rewards_collector()
                        .unwrap_or(&vote_pubkey);
                    (commission_pubkey, commission_pubkey == vote_pubkey)
                } else {
                    (vote_pubkey, true)
                };
                let reward_commission = RewardCommission {
                    commission_bps: (!custom_commission_collector).then_some(commission_bps),
                    commission_lamports,
                    burned_lamports: 0,
                    is_vote_account,
                };
```

**File:** programs/vote/src/vote_state/mod.rs (L866-904)
```rust
impl NewCommissionCollector<'_, '_> {
    /// Validates the collector per SIMD-0232 and returns its pubkey.
    ///
    /// The designated commission collector must either be equal to the vote
    /// account's address OR satisfy ALL of the following constraints:
    ///
    /// 1. Must be a system program owned account.
    /// 2. Must be rent-exempt.
    /// 3. Must not be a reserved account (checked via writable flag).
    pub fn validate_and_resolve_key(
        &self,
        vote_account: &BorrowedInstructionAccount,
        rent: &Rent,
    ) -> Result<Pubkey, InstructionError> {
        match self {
            NewCommissionCollector::VoteAccount => Ok(*vote_account.get_key()),
            NewCommissionCollector::NewAccount(collector_account) => {
                // 1. Must be a system program owned account.
                if collector_account.get_owner() != &system_program::id() {
                    return Err(InstructionError::InvalidAccountOwner);
                }

                // 2. Must be rent-exempt.
                if !rent.is_exempt(
                    collector_account.get_lamports(),
                    collector_account.get_data().len(),
                ) {
                    return Err(InstructionError::InsufficientFunds);
                }

                // 3. Must not be a reserved account (checked via writable flag).
                if !collector_account.is_writable() {
                    return Err(InstructionError::InvalidArgument);
                }

                Ok(*collector_account.get_key())
            }
        }
    }
```
