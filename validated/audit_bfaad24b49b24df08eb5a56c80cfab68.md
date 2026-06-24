Audit Report

## Title
Unbounded Synchronous BFS in SNS `cast_vote_and_cascade_follow` Enables Governance DoS via Follower Flooding - (File: rs/sns/governance/src/governance.rs)

## Summary
The SNS governance canister's `cast_vote_and_cascade_follow` function performs a fully synchronous, unbounded BFS over all follower neurons in a single message execution with no instruction-limit guard. Because any unprivileged user can create neurons and set following relationships on a target neuron without the target's consent, an attacker can flood a victim neuron's follower set up to `MAX_NUMBER_OF_NEURONS_CEILING = 200,000`. When the victim subsequently calls `register_vote`, the synchronous BFS exhausts the IC's per-message instruction budget, causing the update call to trap and the vote to be permanently unrecorded.

## Finding Description
`cast_vote_and_cascade_follow` is a plain synchronous `fn` (not `async fn`) called directly from the synchronous `register_vote`:

- **BFS loop with no instruction guard** (lines 3749–3836): The outer `while !induction_votes.is_empty()` loop collects all follower IDs from `topic_follower_index` and `function_followee_index` (lines 3783–3797), then for each follower performs a `neurons.get()` BTreeMap lookup (O(log N)) and a `vote_from_ballots_following` call (O(max_followees_per_function) ballot lookups) (lines 3803–3825). There is no `is_over_instructions_limit` check, no `noop_self_call_if_over_instructions` await point, and no state-machine checkpointing anywhere in this path.

- **Synchronous call site** (lines 3931–3942): `register_vote` (line 3854, also a plain `fn`) calls `Governance::cast_vote_and_cascade_follow(...)` directly with no async boundary.

- **No cap on inbound followers**: `follow` (line 3962) enforces `max_followees_per_function` (ceiling 15) only on the *outbound* followee list of the calling neuron. There is no corresponding limit on how many neurons may follow a given neuron, confirmed by the absence of any `max_followers` check in the SNS codebase.

- **Contrast with NNS**: `rs/nns/governance/src/voting.rs` lines 150–176 show the NNS equivalent is `async`, uses a `ProposalVotingStateMachine`, and calls `noop_self_call_if_over_instructions(SOFT_VOTING_INSTRUCTIONS_LIMIT, Some(HARD_VOTING_INSTRUCTIONS_LIMIT)).await` to yield across message boundaries. The SNS has no equivalent.

**Exploit flow:**
1. Attacker creates up to `max_number_of_neurons` neurons (ceiling `MAX_NUMBER_OF_NEURONS_CEILING = 200,000`, `rs/sns/governance/src/types.rs` line 386), each staking `neuron_minimum_stake_e8s` tokens.
2. Each attacker neuron calls `follow` targeting the victim neuron on a chosen function/topic. The victim cannot prevent or remove these following relationships.
3. A proposal is created; ballots are allocated for all neurons including all attacker neurons.
4. Victim calls `register_vote`. The synchronous BFS iterates over all 200,000 follower neurons — performing BTreeMap lookups and `vote_from_ballots_following` calls — exhausting the IC's per-message instruction budget. The update call traps, state is rolled back, and the vote is not recorded.
5. The victim cannot successfully retry as long as the follower flood persists. Attacker neurons remain in place until their dissolve delay expires.

## Impact Explanation
This is a High-severity application/platform-level DoS against SNS governance. A victim neuron with significant voting power is permanently denied its vote on any proposal created while the follower flood is active. In an SNS with a small number of legitimate large-stake neurons, silencing one can materially alter governance outcomes — blocking or passing proposals contrary to the victim's intent. This matches the allowed impact: *"Significant SNS security impact with concrete user or protocol harm"* and *"Application/platform-level DoS not based on raw volumetric DDoS."*

## Likelihood Explanation
The attack requires staking tokens across many neurons, imposing a real economic cost. However, `neuron_minimum_stake_e8s` is SNS-configurable and can be set very low, making the cost proportionally small for high-value targets. The following relationship is unilaterally set by the attacker — the victim has no recourse. The attack is persistent (dissolve delays prevent rapid cleanup) and repeatable across proposals. An attacker targeting a specific SNS DAO with low minimum stake and high governance stakes has clear motivation.

## Recommendation
1. Make `register_vote` and `cast_vote_and_cascade_follow` async and introduce a `ProposalVotingStateMachine` equivalent for SNS, mirroring the NNS pattern in `rs/nns/governance/src/voting.rs`.
2. Add `is_over_instructions_limit` checks inside the BFS loop, checkpointing progress to stable state and resuming via a timer job (analogous to `process_voting_state_machines` in NNS).
3. As a complementary defense, enforce a per-neuron cap on inbound followers (a `max_followers_per_neuron` parameter) to bound BFS fan-out, analogous to the existing `max_followees_per_function` cap on outbound following.

## Proof of Concept
```rust
// PocketIC integration test outline:
// 1. Deploy SNS with neuron_minimum_stake_e8s = 1, max_number_of_neurons = 200_000
// 2. Create victim neuron V
// 3. Create N attacker neurons A_0..A_{N-1}, each calling follow(A_i, followees=[V], function_id=X)
// 4. Submit a proposal P of type X
// 5. Call register_vote(V, P, Yes) — expect trap / instruction limit exceeded
// 6. Verify V's ballot on P remains Vote::Unspecified
// 7. Confirm the same call succeeds with N=0 (baseline)
```
The test can be run locally with PocketIC without touching mainnet, satisfying the no-mainnet-testing requirement.