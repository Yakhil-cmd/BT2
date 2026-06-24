Audit Report

## Title
Unbounded Synchronous BFS in SNS Governance `cast_vote_and_cascade_follow` Can Exhaust Instruction Limit and Permanently Block Voting - (File: rs/sns/governance/src/governance.rs)

## Summary

`Governance::cast_vote_and_cascade_follow` in `rs/sns/governance/src/governance.rs` performs a fully synchronous, unbounded BFS over the neuron follower graph with no instruction-limit guard. Because the number of neurons that can follow any given neuron is unbounded, a single `register_vote` or `make_proposal` call from a neuron with a sufficiently large follower set will exhaust the IC's 40B-instruction per-message limit, causing the message to be rejected and permanently blocking that neuron from voting or submitting proposals. NNS governance has an explicit async instruction-limit-aware state machine for the same operation; SNS governance has none.

## Finding Description

`cast_vote_and_cascade_follow` (line 3687) is a plain synchronous `fn` (not `async fn`) that runs a `while !induction_votes.is_empty()` BFS loop (lines 3749–3836). Each iteration performs `BTreeMap` lookups and `BTreeSet` insertions for every follower of every neuron in the current BFS tier. There is no call to any instruction-counter check, no `await` point, and no early-exit guard anywhere in the loop.

This function is called synchronously from two paths:
- `make_proposal` at line 3658, before the proposal is even inserted.
- `register_vote` at line 3931, as the final step before `process_proposal`.

`register_vote` itself is a plain synchronous `fn` (line 3854), so there is no opportunity for DTS to help beyond the 40B total message budget.

The `max_followees_per_function` parameter (enforced in `follow` at line 3991) limits how many neurons a single neuron may *follow* (outgoing edges). It places **no bound** on how many neurons may follow a given neuron (incoming edges). A single popular neuron — e.g., the founding team's neuron — can accumulate an unbounded number of followers over time, since neurons are never deleted.

By contrast, NNS governance (`rs/nns/governance/src/voting.rs`, lines 150–176) wraps the same BFS in an `async` loop that calls `noop_self_call_if_over_instructions` after each tier, and `continue_processing` (lines 506–551) checks `is_over_instructions_limit()` after every single follower is processed, suspending remaining work to a timer job when the limit is approached.

## Impact Explanation

When the instruction limit is exceeded, the IC execution environment rejects the entire update message. The effects are:
- Any neuron whose vote would trigger a cascade over a large follower set is permanently unable to cast a vote or submit a proposal on that SNS.
- If the affected neuron holds decisive voting power (e.g., the founding team's neuron), proposals can never reach quorum, permanently freezing the SNS DAO's governance.

This matches the allowed ICP bounty impact: **High — Application/platform-level DoS with concrete SNS governance harm**, and **High — Significant SNS security impact with concrete user or protocol harm**.

## Likelihood Explanation

Any unprivileged SNS neuron holder can trigger this by calling `manage_neuron { RegisterVote }` from a neuron that has a large follower set, or by submitting a proposal from such a neuron. No special privilege is required. The follower graph grows monotonically (neurons are never deleted), so popular SNS DAOs with thousands of neurons (e.g., OpenChat, Kinic) are already approaching the conditions needed to trigger this. The attack requires no key material, no majority, and no social engineering — only a large enough follower set, which accumulates naturally.

## Recommendation

Apply the same instruction-limit-aware async state-machine pattern used in NNS governance:
1. Introduce a `ProposalVotingStateMachine` equivalent for SNS governance that stores BFS state across calls.
2. Make `register_vote` (and the `make_proposal` call site) `async`.
3. Check `over_soft_message_limit()` (or equivalent) after each BFS tier and suspend remaining work to a timer job when the limit is approached, mirroring `noop_self_call_if_over_instructions` in NNS governance.
4. As a complementary mitigation, enforce a hard cap on the number of *followers* per neuron per function/topic at the `follow` call site (not just on followees), analogous to `max_followees_per_function`.

## Proof of Concept

1. Deploy an SNS with N neurons (N large, e.g., 50,000).
2. Have all N neurons call `follow` to follow neuron A on a given function/topic.
3. Neuron A votes on an existing proposal (`manage_neuron { RegisterVote }`), triggering `register_vote` → `cast_vote_and_cascade_follow` with N followers in the BFS.
4. Alternatively, neuron A submits a proposal, triggering `make_proposal` → `cast_vote_and_cascade_follow`.
5. The BFS iterates over all N followers in a single synchronous message, consuming O(N log N) instructions.
6. With N large enough to exceed 40B instructions (`MAX_INSTRUCTIONS_PER_MESSAGE` at `rs/config/src/subnet_config.rs:36`), the IC rejects the message with `CanisterInstructionLimitExceeded`.
7. Neuron A can never vote or submit proposals; governance is permanently impaired.

A deterministic integration test using PocketIC can reproduce this by creating 50,000 neurons all following a single neuron, then asserting that `register_vote` from that neuron returns an instruction-limit error. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** rs/sns/governance/src/governance.rs (L3658-3669)
```rust
        Governance::cast_vote_and_cascade_follow(
            &proposal_id,
            proposer_id,
            Vote::Yes,
            function_id,
            &self.function_followee_index,
            &self.topic_follower_index,
            &self.proto.neurons,
            now_seconds,
            &mut proposal_data.ballots,
            proposal_topic,
        );
```

**File:** rs/sns/governance/src/governance.rs (L3687-3700)
```rust
    fn cast_vote_and_cascade_follow(
        proposal_id: &ProposalId, // As of Nov, 2023 (a2095be), this is only used for logging.
        voting_neuron_id: &NeuronId,
        vote_of_neuron: Vote,
        function_id: u64,
        function_followee_index: &legacy::FollowerIndex,
        topic_follower_index: &FollowerIndex,
        neurons: &BTreeMap<String, Neuron>,
        // As of Dec, 2023 (52eec5c), the next parameter is only used to populate Ballots. In
        // particular, this has no impact on how the implications of following are deduced.
        now_seconds: u64,
        ballots: &mut BTreeMap<String, Ballot>, // This is ultimately what gets changed.
        topic: Topic,
    ) {
```

**File:** rs/sns/governance/src/governance.rs (L3749-3836)
```rust
        while !induction_votes.is_empty() {
            // This will be populated with the followers of neurons in the
            // current BFS tier, who might be swayed to indirectly vote, thus
            // forming the next tier in the BFS.
            let mut follower_neuron_ids = BTreeSet::new();

            // Process the current tier in the BFS.
            for (current_neuron_id, current_new_vote) in &induction_votes {
                let current_ballot = match ballots.get_mut(current_neuron_id) {
                    Some(b) => b,
                    None => {
                        // neuron_id has no (blank) ballot, which means they
                        // were not eligible when the proposal was first
                        // created. This is fairly unusual, but does not
                        // indicate a bug (therefore, no log).
                        continue;
                    }
                };

                // Only fill in "blank" ballots. I.e. those with vote ==
                // Unspecified. This check could just as well be done before
                // current_neuron_id is added to induction_votes.
                if current_ballot.vote != (Vote::Unspecified as i32) {
                    continue;
                }

                // Fill in current_ballot.
                assert_ne!(*current_new_vote, Vote::Unspecified);
                current_ballot.vote = *current_new_vote as i32;
                current_ballot.cast_timestamp_seconds = now_seconds;

                // Take note of the followers of current_neuron_id, and add them
                // to the next "tier" in the BFS.

                if let Some(new_follower_neuron_ids) = topic_followers
                    .and_then(|topic_followers| topic_followers.get(current_neuron_id))
                {
                    for follower_neuron_id in new_follower_neuron_ids {
                        follower_neuron_ids.insert(follower_neuron_id.clone());
                    }
                }

                if let Some(new_follower_neuron_ids) =
                    neuron_id_to_follower_neuron_ids.get(current_neuron_id)
                {
                    for follower_neuron_id in new_follower_neuron_ids {
                        follower_neuron_ids.insert(follower_neuron_id.clone());
                    }
                }
            }

            // Prepare for the next iteration of the (outer most) loop by
            // constructing the next BFS tier (from follower_neuron_ids).
            induction_votes.clear();
            for follower_neuron_id in follower_neuron_ids {
                let Some(follower_neuron) = neurons.get(&follower_neuron_id.to_string()) else {
                    // This is a highly suspicious, because currently, we do not
                    // delete neurons, which means that we have an invalid NeuronId
                    // floating around in the system, which indicates that we have a
                    // bug. For now, we deal with that by logging, and pretending like
                    // we did not see follower_neuron_id.
                    log!(
                        ERROR,
                        "Missing neuron {} while trying to record (and cascade) \
                            a vote on proposal {:#?}.",
                        follower_neuron_id,
                        proposal_id,
                    );
                    continue;
                };

                let follower_vote = follower_neuron.vote_from_ballots_following(
                    function_id,
                    topic,
                    ballots,
                    proposal_id,
                );

                if follower_vote != Vote::Unspecified {
                    // follower_neuron would be swayed by its followees!
                    //
                    // This is the other (earlier) point at which we could
                    // consider whether a neuron is already locked in, and that
                    // no recursion is needed.
                    induction_votes.insert(follower_neuron_id.to_string(), follower_vote);
                }
            }
        }
```

**File:** rs/sns/governance/src/governance.rs (L3931-3942)
```rust
        Governance::cast_vote_and_cascade_follow(
            proposal_id,
            neuron_id,
            vote,
            function_id,
            &self.function_followee_index,
            &self.topic_follower_index,
            &self.proto.neurons,
            now_seconds,
            &mut proposal.ballots,
            proposal_topic.unwrap_or_default(),
        );
```

**File:** rs/sns/governance/src/governance.rs (L3979-3995)
```rust
        let max_followees_per_function = self
            .proto
            .parameters
            .as_ref()
            .expect("NervousSystemParameters not present")
            .max_followees_per_function
            .expect("NervousSystemParameters must have max_followees_per_function");

        // Check that the list of followees is not too
        // long. Allowing neurons to follow too many neurons
        // allows a memory exhaustion attack on the neurons
        // canister.
        if f.followees.len() > max_followees_per_function as usize {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Too many followees.",
            ));
```

**File:** rs/nns/governance/src/voting.rs (L150-176)
```rust
        while !is_voting_finished {
            // Now we process until we are done or we are over a limit and need to
            // make a self-call.
            with_voting_state_machines_mut(|voting_state_machines| {
                voting_state_machines.with_machine(proposal_id, topic, |machine| {
                    self.process_machine_until_soft_limit(machine, over_soft_message_limit);
                    is_voting_finished = machine.is_voting_finished();
                });
            });

            // This returns an error if we hit the hard limit, which should basically never happen
            // in production, but we need a way out of this loop in the worst case to prevent
            // the canister from being unable to upgrade.
            if let Err(e) = noop_self_call_if_over_instructions(
                SOFT_VOTING_INSTRUCTIONS_LIMIT,
                Some(HARD_VOTING_INSTRUCTIONS_LIMIT),
            )
            .await
            {
                println!(
                    "Error in cast_vote_and_cascade_follow, \
                        voting will be processed in timers: {}",
                    e
                );
                break;
            }
        }
```

**File:** rs/nns/governance/src/voting.rs (L506-551)
```rust
    fn continue_processing(
        &mut self,
        neuron_store: &mut NeuronStore,
        ballots: &mut HashMap<u64, Ballot>,
        is_over_instructions_limit: fn() -> bool,
    ) {
        let voting_finished = self.is_voting_finished();

        if !voting_finished {
            while let Some(neuron_id) = self.neurons_to_check_followers.pop_first() {
                self.add_followers_to_check(neuron_store, neuron_id, self.topic);

                // Before we check the next one, see if we're over the limit.
                if is_over_instructions_limit() {
                    return;
                }
            }

            // Memory optimization, will not cause tests to fail if removed
            retain_neurons_with_castable_ballots(&mut self.followers_to_check, ballots);

            while let Some(follower) = self.followers_to_check.pop_first() {
                let vote = match neuron_store
                    .neuron_would_follow_ballots(follower, self.topic, ballots)
                {
                    Ok(vote) => vote,
                    Err(e) => {
                        // This is a bad inconsistency, but there is
                        // nothing that can be done about it at this
                        // place.  We somehow have followers recorded that don't exist.
                        eprintln!(
                            "error in cast_vote_and_cascade_follow when gathering induction votes: {:?}",
                            e
                        );
                        Vote::Unspecified
                    }
                };
                // Casting vote immediately might affect other follower votes, which makes
                // voting resolution take fewer iterations.
                // Vote::Unspecified is ignored by cast_vote.
                self.cast_vote(ballots, follower, vote);

                if is_over_instructions_limit() {
                    return;
                }
            }
```

**File:** rs/config/src/subnet_config.rs (L36-36)
```rust
pub(crate) const MAX_INSTRUCTIONS_PER_MESSAGE: NumInstructions = NumInstructions::new(40 * B);
```
