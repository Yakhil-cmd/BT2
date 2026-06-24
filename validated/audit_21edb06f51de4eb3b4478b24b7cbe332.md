Audit Report

## Title
SNS Governance `distribute_rewards` Unbounded Neuron Iteration Causes Permanent Reward Liveness Failure - (File: `rs/sns/governance/src/governance.rs`)

## Summary

The SNS Governance canister's `distribute_rewards` function iterates over all voting neurons in a single synchronous call with no instruction-limit guard. If the neuron count grows large enough to exhaust the IC per-message instruction budget, the message traps and rolls back all state changes. Because `latest_reward_event` is only written after the loop completes, `should_distribute_rewards()` returns `true` again on the next timer tick, re-attempting the identical unbounded loop indefinitely. Voting reward distribution is permanently halted for the affected SNS DAO.

## Finding Description

`run_periodic_tasks` calls `distribute_rewards` synchronously whenever `should_distribute_rewards()` returns `true`: [1](#0-0) 

Inside `distribute_rewards`, after computing `neuron_id_to_reward_shares` from all proposal ballots, the function enters an unbounded `for` loop over every neuron that voted: [2](#0-1) 

There is no call to `is_message_over_threshold` or any equivalent instruction-limit guard anywhere in this loop. A grep for `is_message_over_threshold`, `DISTRIBUTION_MESSAGE_LIMIT`, or any instruction-counter check in `rs/sns/governance/**` returns zero matches.

The `latest_reward_event` is only written, and proposals only settled, **after** the loop completes: [3](#0-2) 

If the loop traps due to instruction exhaustion, all state changes roll back. `should_distribute_rewards()` checks only elapsed time against `round_duration_seconds`: [4](#0-3) 

Because `latest_reward_event` was never advanced, this condition remains `true` on every subsequent timer invocation, causing the same unbounded loop to be re-attempted and re-trapped indefinitely.

By contrast, NNS Governance was explicitly fixed (Proposal 135702) to use a batched, resumable state machine with an instruction-limit guard: [5](#0-4) [6](#0-5) 

The NNS CHANGELOG explicitly documents this as a real production fix: [7](#0-6) 

The SNS governance CHANGELOG contains no equivalent remediation.

## Impact Explanation

Once the neuron-iteration loop exceeds the IC per-message instruction limit (~40 billion instructions), every invocation of `run_periodic_tasks` traps at the same point. Voting rewards are never distributed again; neuron maturity stops accruing permanently, breaking the economic incentive for governance participation in the affected SNS DAO. This is a concrete, irreversible application-level DoS on SNS governance reward distribution — matching the allowed impact class: **High ($2,000–$10,000): Application/platform-level DoS or significant SNS security impact with concrete user or protocol harm.**

## Likelihood Explanation

No adversarial action is required. Any SNS DAO that grows organically to a sufficient number of active voting neurons will trigger this. The SNS `max_number_of_neurons` parameter is configurable by the DAO itself and can be set to values well above the threshold at which the loop would exhaust the instruction budget. The NNS governance team already confirmed this is a real, non-theoretical failure mode by issuing an emergency fix for the identical bug in NNS Governance. The SNS canister did not receive the same remediation.

## Recommendation

Apply the same batched-distribution pattern already implemented in NNS Governance:

1. After computing `neuron_id_to_reward_shares`, immediately advance `latest_reward_event` and settle proposals (so they are not re-processed on the next tick).
2. Store the pending per-neuron reward map in stable memory (analogous to `RewardsDistributionStateMachine`).
3. Distribute maturity to neurons in a separate recurring timer task that calls `is_message_over_threshold` after each neuron and breaks out of the loop, resuming in the next message if the limit is reached — mirroring `continue_processing` in `rs/nns/governance/src/reward/distribution.rs`.

## Proof of Concept

1. Deploy an SNS DAO and accumulate a large number of neurons (e.g., 50,000+), all of which vote on proposals, so that `neuron_id_to_reward_shares` is large.
2. Wait for the reward round timer to fire `run_periodic_tasks` → `distribute_rewards`.
3. The loop at line 5954 iterates over all entries; after enough neurons, the IC instruction counter exceeds the per-message limit and the message traps.
4. All state changes roll back; `latest_reward_event` is unchanged; `considered_proposals` remain in `ReadyToSettle`.
5. The next timer fires; `should_distribute_rewards()` returns `true` (same epoch, same proposals). The identical loop runs and traps again.
6. Voting rewards are permanently halted.

A deterministic integration test can reproduce this by constructing a mock environment with a large `neuron_id_to_reward_shares` map and an instruction counter stub that returns exhausted after N iterations, then asserting that `latest_reward_event` is never advanced across repeated calls to `distribute_rewards`.

### Citations

**File:** rs/sns/governance/src/governance.rs (L5503-5513)
```rust
        let should_distribute_rewards = self.should_distribute_rewards();

        // Getting the total governance token supply from the ledger is expensive enough
        // that we don't want to do it on every call to `run_periodic_tasks`. So
        // we only fetch it when it's needed, which is when rewards should be
        // distributed
        if should_distribute_rewards {
            match self.ledger.total_supply().await {
                Ok(supply) => {
                    // Distribute rewards
                    self.distribute_rewards(supply);
```

**File:** rs/sns/governance/src/governance.rs (L5725-5753)
```rust
    fn should_distribute_rewards(&self) -> bool {
        let now = self.env.now();

        let voting_rewards_parameters = match &self
            .nervous_system_parameters_or_panic()
            .voting_rewards_parameters
        {
            None => return false,
            Some(ok) => ok,
        };
        let seconds_since_last_reward_event = now.saturating_sub(
            self.latest_reward_event()
                .end_timestamp_seconds
                .unwrap_or_default(),
        );

        let round_duration_seconds = match voting_rewards_parameters.round_duration_seconds {
            Some(s) => s,
            None => {
                log!(
                    ERROR,
                    "round_duration_seconds unset:\n{:#?}",
                    voting_rewards_parameters,
                );
                return false;
            }
        };

        seconds_since_last_reward_event > round_duration_seconds
```

**File:** rs/sns/governance/src/governance.rs (L5954-5997)
```rust
            for (neuron_id, neuron_reward_shares) in neuron_id_to_reward_shares {
                let neuron: &mut Neuron = match self.get_neuron_result_mut(&neuron_id) {
                    Ok(neuron) => neuron,
                    Err(err) => {
                        log!(
                            ERROR,
                            "Cannot find neuron {}, despite having voted with power {} \
                             in the considered reward period. The reward that should have been \
                             distributed to this neuron is simply skipped, so the total amount \
                             of distributed reward for this period will be lower than the maximum \
                             allowed. Underlying error: {:?}.",
                            neuron_id,
                            neuron_reward_shares,
                            err
                        );
                        continue;
                    }
                };

                // Dividing before multiplying maximizes our chances of success.
                let neuron_reward_e8s =
                    rewards_purse_e8s * (neuron_reward_shares / total_reward_shares);

                // Round down, and convert to u64.
                let neuron_reward_e8s = u64::try_from(neuron_reward_e8s).unwrap_or_else(|err| {
                    panic!(
                        "Calculating reward for neuron {neuron_id:?}:\n\
                             neuron_reward_shares: {neuron_reward_shares}\n\
                             rewards_purse_e8s: {rewards_purse_e8s}\n\
                             total_reward_shares: {total_reward_shares}\n\
                             err: {err}",
                    )
                });
                // If the neuron has auto-stake-maturity on, add the new maturity to the
                // staked maturity, otherwise add it to the un-staked maturity.
                if neuron.auto_stake_maturity.unwrap_or(false) {
                    neuron.staked_maturity_e8s_equivalent = Some(
                        neuron.staked_maturity_e8s_equivalent.unwrap_or(0) + neuron_reward_e8s,
                    );
                } else {
                    neuron.maturity_e8s_equivalent += neuron_reward_e8s;
                }
                distributed_e8s_equivalent += neuron_reward_e8s;
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

**File:** rs/nns/governance/src/reward/distribution.rs (L42-52)
```rust
    pub fn distribute_pending_rewards(&mut self) -> bool {
        let is_over_instructions_limit = || is_message_over_threshold(DISTRIBUTION_MESSAGE_LIMIT);
        with_rewards_distribution_state_machine_mut(|rewards_distribution_state_machine| {
            rewards_distribution_state_machine.with_next_distribution(|(_, distribution)| {
                distribution
                    .continue_processing(&mut self.neuron_store, is_over_instructions_limit);
            });
            // Work left?
            !rewards_distribution_state_machine.distributions.is_empty()
        })
    }
```

**File:** rs/nns/governance/src/reward/distribution.rs (L154-187)
```rust
    fn continue_processing(
        &mut self,
        neuron_store: &mut NeuronStore,
        is_over_instructions_limit: fn() -> bool,
    ) {
        while let Some((id, reward_e8s)) = self.rewards.pop_first() {
            match neuron_store.with_neuron_mut(&id, |neuron| {
                let auto_stake = neuron.auto_stake_maturity.unwrap_or(false);
                if auto_stake {
                    neuron.staked_maturity_e8s_equivalent = Some(
                        neuron
                            .staked_maturity_e8s_equivalent
                            .unwrap_or_default()
                            .saturating_add(reward_e8s),
                    );
                } else {
                    neuron.maturity_e8s_equivalent =
                        neuron.maturity_e8s_equivalent.saturating_add(reward_e8s);
                }
            }) {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "{}Error rewarding neuron {:?} during reward_distribution.\
                    This should not be possible as neuron existence is checked when \
                    rewards are calculated: {}",
                        LOG_PREFIX, id, e
                    );
                }
            };
            if is_over_instructions_limit() {
                break;
            }
        }
```

**File:** rs/nns/governance/CHANGELOG.md (L654-669)
```markdown
    * Compared to the last time it was enabled, several improvements were made:
        * Distribute rewards is moved to timer, and has a mechanism to distribute in batches in
          multiple messages.
        * Unstaking maturity task has a limit of 100 neurons per message, which prevents it from
          exceeding instruction limit.
        * The execution of `ApproveGenesisKyc` proposals have a limit of 1000 neurons, above which
          the proposal will fail.
        * More benchmarks were added.
* Enable timer task metrics for better observability.

## Changed

* Voting Rewards will be scheduled by a timer instead of by heartbeats.
* Unstaking maturity task will be processing up to 100 neurons in a single message, to avoid
  exceeding the instruction limit in a single execution.
* Voting Rewards will be distributed asynchronously in the background after being calculated.
```
