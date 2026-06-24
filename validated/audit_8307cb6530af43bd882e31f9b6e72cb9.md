The code behavior matches the claim exactly. Let me verify the full flow one more time to be certain.

Audit Report

## Title
SNS Governance Rewards Purse Permanently Lost When `total_reward_shares` Is Zero With Settled Proposals - (File: rs/sns/governance/src/governance.rs)

## Summary

In `distribute_rewards`, when `total_reward_shares == dec!(0)` but `considered_proposals` is non-empty, the entire `rewards_purse_e8s` for that round is silently destroyed. The distribution loop is skipped, yet all proposals are still settled and their ballots cleared. Because `RewardEvent.settled_proposals` is non-empty, `rewards_rolled_over()` returns `false` and `e8s_equivalent_to_be_rolled_over()` returns `0`, so the next round starts with a fresh purse and the current round's accrued maturity is permanently gone.

## Finding Description

`distribute_rewards` computes `rewards_purse_e8s` starting from the previous event's rolled-over amount plus the current round's supply × rate contribution: [1](#0-0) 

It then builds `neuron_id_to_reward_shares` from ballots of `considered_proposals`. If no neuron cast an eligible vote on any of those proposals, `total_reward_shares` sums to `Decimal::ZERO`. The guard at L5946 logs a warning and skips the distribution loop entirely: [2](#0-1) 

Execution then falls through unconditionally to the proposal-settlement loop, which sets `reward_event_end_timestamp_seconds`, increments `reward_event_round`, and clears ballots for every proposal in `considered_proposals`: [3](#0-2) 

The resulting `RewardEvent` is stored with `settled_proposals: considered_proposals` (non-empty): [4](#0-3) 

The rollover predicate checks only whether `settled_proposals` is empty: [5](#0-4) 

Because it is not empty, `e8s_equivalent_to_be_rolled_over` returns `0`: [6](#0-5) 

The next call to `distribute_rewards` therefore initialises `rewards_purse_e8s` from `0` rather than from the lost amount, permanently discarding the maturity that accrued in the affected round. The NNS governance exhibits the structurally identical pattern under its `total_voting_rights < 0.001` guard: [7](#0-6) [8](#0-7) 

## Impact Explanation

Every round in which this condition fires causes a permanent, silent destruction of SNS governance token maturity equal to `rewards_purse_e8s` for that round (token supply × reward rate × round duration, plus any previously rolled-over amount). Neuron holders are entitled to this maturity but will never receive it; the governance canister continues operating normally with no on-chain indication of the loss. This constitutes a significant SNS governance impact with concrete, unrecoverable financial harm to neuron holders, matching the **High ($2,000–$10,000)** impact class: "Significant … SNS … security impact with concrete user or protocol harm."

## Likelihood Explanation

The trigger — `total_reward_shares == 0` while `considered_proposals` is non-empty — requires that every proposal ready to settle received zero eligible votes. This arises naturally (no attacker required) in: a newly launched SNS whose neurons have not yet reached the minimum dissolve delay; an SNS where all neurons have dissolved or been merged/split between proposal creation and settlement; or any round of governance inactivity. Because SNS deployments are often small and lightly governed, this is a realistic operational condition, not a contrived edge case. No special privileges are required; the condition can also be induced by any participant who submits a proposal and ensures no eligible neuron votes before the deadline.

## Recommendation

Before settling proposals, check whether `total_reward_shares == dec!(0)`. If so, either:

1. **Skip settling** — do not advance `reward_event_end_timestamp_seconds` or clear ballots for any proposal in `considered_proposals`, leaving them for the next round; or
2. **Force rollover** — record the `RewardEvent` with an empty `settled_proposals` list (or set a dedicated `rolled_over` flag) so that `rewards_rolled_over()` returns `true` and `e8s_equivalent_to_be_rolled_over()` carries the full purse forward.

Option 1 is simpler and preserves the ability for neurons to vote in the next round. Option 2 settles proposals but preserves the purse. Either fix must also be applied to the analogous NNS path guarded by `total_voting_rights < 0.001`.

## Proof of Concept

1. Deploy an SNS with `voting_rewards_parameters` configured (non-zero reward rate and round duration) and a non-zero token supply.
2. Ensure all neurons are below the minimum dissolve delay required to vote (or have fully dissolved).
3. Submit a governance proposal. It enters the voting period with ballots for all eligible neurons, but since none meet the dissolve-delay threshold, no ballot carries eligible voting power.
4. Advance time past the proposal's voting deadline so it becomes `ReadyToSettle`.
5. Trigger `run_periodic_tasks` → `distribute_rewards` is called. `rewards_purse_e8s > 0`. `neuron_id_to_reward_shares` is empty → `total_reward_shares == dec!(0)`.
6. Observe: the warning is logged; the distribution loop is skipped; the proposal is settled with ballots cleared.
7. Inspect `latest_reward_event`: `settled_proposals` is non-empty, `distributed_e8s_equivalent == 0`, `total_available_e8s_equivalent > 0`.
8. Trigger a second `distribute_rewards` call. Observe that `rewards_purse_e8s` is computed from `e8s_equivalent_to_be_rolled_over() == 0` — the previous round's purse is gone.
9. A deterministic PocketIC or unit test can assert this invariant: after a zero-vote settlement round, `sum(neuron.maturity_e8s_equivalent)` has not increased by the expected `rewards_purse_e8s`, and the subsequent round's starting purse does not include the lost amount.

### Citations

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

**File:** rs/sns/governance/src/governance.rs (L6013-6081)
```rust
        for pid in &considered_proposals {
            // Before considering a proposal for reward, it must be fully processed --
            // because we're about to clear the ballots, so no further processing will be
            // possible.
            self.process_proposal(pid.id);

            let p = match self.get_proposal_data_mut(*pid) {
                Some(p) => p,
                None => {
                    log!(
                        ERROR,
                        "Cannot find proposal {}, despite it being considered for rewards distribution.",
                        pid.id
                    );
                    debug_assert!(
                        false,
                        "It appears that proposal {} has been deleted out from under us \
                         while we were distributing rewards. This should never happen. \
                         In production, this would be quietly swept under the rug and \
                         we would continue processing. Current state (Governance):\n{:#?}",
                        pid.id, self.proto,
                    );
                    continue;
                }
            };

            if p.status() == ProposalDecisionStatus::Open {
                log!(
                    ERROR,
                    "Proposal {} was considered for reward distribution despite \
                     being open. We will now force the proposal's status to be Rejected.",
                    pid.id
                );
                debug_assert!(
                    false,
                    "This should be unreachable. Current governance state:\n{:#?}",
                    self.proto,
                );

                // The next two statements put p into the Rejected status. Thus,
                // process_proposal will consider that it has nothing more to do
                // with the p.
                p.decided_timestamp_seconds = now;
                p.latest_tally = Some(Tally {
                    timestamp_seconds: now,
                    yes: 0,
                    no: 0,
                    total: 0,
                });
                debug_assert_eq!(
                    p.status(),
                    ProposalDecisionStatus::Rejected,
                    "Failed to force ProposalData status to become Rejected. p:\n{p:#?}",
                );
            }

            // This is where the proposal becomes Settled, at least in the eyes
            // of the ProposalData::reward_status method.
            p.reward_event_end_timestamp_seconds = Some(reward_event_end_timestamp_seconds);
            p.reward_event_round = new_reward_event_round;

            // Ballots are used to determine two things:
            //   1. (obviously and primarily) whether to execute the proposal.
            //   2. rewards
            // At this point, we no longer need ballots for either of these
            // things, and since they take up a fair amount of space, we take
            // this opportunity to jettison them.
            p.ballots.clear();
        }
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

**File:** rs/nns/governance/src/governance.rs (L6712-6719)
```rust
        let reward_distribution = if total_voting_rights < 0.001 {
            println!(
                "{}WARNING: total_voting_rights == {}, even though considered_proposals \
                 is nonempty (see earlier log). Therefore, we skip incrementing maturity \
                 to avoid dividing by zero (or super small number).",
                LOG_PREFIX, total_voting_rights,
            );
            None
```

**File:** rs/nns/governance/src/reward/calculation.rs (L120-126)
```rust
    pub(crate) fn e8s_equivalent_to_be_rolled_over(&self) -> u64 {
        if self.rewards_rolled_over() {
            self.total_available_e8s_equivalent
        } else {
            0
        }
    }
```
