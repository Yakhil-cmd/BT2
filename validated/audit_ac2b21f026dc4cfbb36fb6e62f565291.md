The code confirms the claim. Here is the validation:

---

Audit Report

## Title
SNS Voting Rewards Permanently Lost When Proposals Settle With Zero Voter Participation - (File: rs/sns/governance/src/governance.rs, rs/sns/governance/src/types.rs)

## Summary
In `distribute_rewards`, when proposals are settled but no neuron cast an eligible vote (`total_reward_shares == dec!(0)`), the function logs a warning and skips maturity distribution but does **not** return early. It proceeds to write a new `RewardEvent` with `settled_proposals` populated and `distributed_e8s_equivalent = 0`. Because `rewards_rolled_over()` only returns `true` when `settled_proposals.is_empty()`, the entire accumulated rewards purse — including any prior rolled-over balance — is permanently discarded on the next call to `distribute_rewards`.

## Finding Description
**Root cause — `rewards_rolled_over()` checks the wrong condition:** [1](#0-0) 

`rewards_rolled_over()` returns `true` only when `settled_proposals` is empty. `e8s_equivalent_to_be_rolled_over()` therefore returns `0` whenever any proposals were settled, regardless of whether any rewards were actually distributed. [2](#0-1) 

**Trigger path in `distribute_rewards`:**

1. `rewards_purse_e8s` is computed, including any rolled-over balance from prior rounds. [3](#0-2) 

2. When `total_reward_shares == dec!(0)`, the function logs a warning and skips the maturity loop, leaving `distributed_e8s_equivalent = 0`. It does **not** return. [4](#0-3) 

3. Execution continues: proposals are settled (ballots cleared, `reward_event_end_timestamp_seconds` stamped), and a new `RewardEvent` is written with `settled_proposals: considered_proposals` (non-empty) and `distributed_e8s_equivalent: 0`. [5](#0-4) 

4. On the next call to `distribute_rewards`, `e8s_equivalent_to_be_rolled_over()` is invoked on this event. Because `settled_proposals` is non-empty, `rewards_rolled_over()` returns `false`, so the rollover contribution is `0`. The entire prior purse is gone. [6](#0-5) 

The proto documentation confirms the rollover mechanism was only designed for the no-proposals case, not the zero-voter-but-settled-proposals case: [7](#0-6) 

## Impact Explanation
This is a **High** severity finding. Any SNS voting rewards accumulated during a round in which proposals settle but no neuron casts an eligible vote are permanently destroyed — no minting occurs, no neuron receives maturity, and no recovery path exists. The loss scales with `supply × reward_rate × round_duration`. For a newly launched SNS with a high initial reward rate (e.g., 10% annualized), a single missed round represents a material fraction of the expected annual inflation budget. This constitutes a significant SNS governance security impact with concrete, irreversible user and protocol harm, matching the High impact class: *"Significant SNS... security impact with concrete user or protocol harm."*

## Likelihood Explanation
The condition is reachable by any unprivileged user. Any account holding enough SNS tokens to pay the proposal rejection fee can submit a proposal. If the SNS community fails to vote before the voting period expires, `total_reward_shares == 0` and the purse is lost. This is especially likely during the initial launch period of a new SNS, when neurons may not yet have configured following relationships. No special privileges, governance majority, or key compromise is required.

## Recommendation
Change `rewards_rolled_over()` to check whether rewards were actually distributed, not merely whether proposals were settled:

```rust
pub(crate) fn rewards_rolled_over(&self) -> bool {
    self.settled_proposals.is_empty()
        || (self.distributed_e8s_equivalent == 0
            && self.total_available_e8s_equivalent.unwrap_or(0) > 0)
}
```

Alternatively, `e8s_equivalent_to_be_rolled_over` could unconditionally return `total_available_e8s_equivalent - distributed_e8s_equivalent`, which is the correct undistributed balance regardless of whether proposals were settled.

## Proof of Concept
1. Launch an SNS with `VotingRewardsParameters`: `round_duration = 7 days`, `initial_rate = 10%`.
2. Submit a proposal and allow it to be rejected by timeout (no neuron votes). The proposal becomes `ReadyToSettle`.
3. `run_periodic_tasks()` calls `distribute_rewards(supply)`:
   - `rewards_purse_e8s = supply * 0.10 / 52` (non-zero).
   - `considered_proposals = [proposal_1]` (non-empty).
   - `total_reward_shares = dec!(0)` (no votes cast).
   - Warning is logged; maturity loop is skipped; `distributed_e8s_equivalent = 0`.
   - New `RewardEvent` written: `settled_proposals=[proposal_1]`, `distributed=0`, `total_available=purse`.
4. Next round: `distribute_rewards()` called again.
   - `e8s_equivalent_to_be_rolled_over()` → `rewards_rolled_over()` → `settled_proposals.is_empty() = false` → returns `0`.
   - `rewards_purse_e8s` starts from `0` rollover; the entire prior purse is permanently lost.

A deterministic integration test using `PocketIC` or the existing SNS governance test harness can reproduce this by asserting that `latest_reward_event().total_available_e8s_equivalent` is carried forward when `distributed_e8s_equivalent == 0` and `settled_proposals` is non-empty.

### Citations

**File:** rs/sns/governance/src/types.rs (L2054-2060)
```rust
    pub(crate) fn e8s_equivalent_to_be_rolled_over(&self) -> u64 {
        if self.rewards_rolled_over() {
            self.total_available_e8s_equivalent.unwrap_or_default()
        } else {
            0
        }
    }
```

**File:** rs/sns/governance/src/types.rs (L2064-2067)
```rust
    /// Whether this is a "rollover event", where no rewards were distributed.
    pub(crate) fn rewards_rolled_over(&self) -> bool {
        self.settled_proposals.is_empty()
    }
```

**File:** rs/sns/governance/src/governance.rs (L5854-5875)
```rust
        let rewards_purse_e8s = {
            let mut result = Decimal::from(
                self.latest_reward_event()
                    .e8s_equivalent_to_be_rolled_over(),
            );
            let supply = i2d(supply.get_e8s());

            for i in 1..=new_rounds_count {
                let seconds_since_genesis = round_duration_seconds
                    .saturating_mul(i)
                    .saturating_add(reward_start_timestamp_seconds)
                    .saturating_sub(self.proto.genesis_timestamp_seconds);

                let current_reward_rate = voting_rewards_parameters.reward_rate_at(
                    crate::reward::Instant::from_seconds_since_genesis(i2d(seconds_since_genesis)),
                );

                result += current_reward_rate * voting_rewards_parameters.round_duration() * supply;
            }

            result
        };
```

**File:** rs/sns/governance/src/governance.rs (L5946-5952)
```rust
        if total_reward_shares == dec!(0) {
            log!(
                ERROR,
                "Warning: total_reward_shares is 0. Therefore, we skip increasing \
                 neuron maturity. neuron_id_to_reward_shares: {:#?}",
                neuron_id_to_reward_shares,
            );
```

**File:** rs/sns/governance/src/governance.rs (L6084-6092)
```rust
        self.proto.latest_reward_event = Some(RewardEvent {
            round: new_reward_event_round,
            actual_timestamp_seconds: now,
            settled_proposals: considered_proposals,
            distributed_e8s_equivalent,
            end_timestamp_seconds: Some(reward_event_end_timestamp_seconds),
            rounds_since_last_distribution: Some(new_rounds_count),
            total_available_e8s_equivalent,
        })
```

**File:** rs/sns/governance/proto/ic_sns_governance/pb/v1/governance.proto (L1399-1402)
```text
  // 2. Rollover: We tried to distribute rewards, but there were no proposals
  //    settled to distribute rewards for.
  //
  // In both of these cases, the rewards purse rolls over into the next round.
```
