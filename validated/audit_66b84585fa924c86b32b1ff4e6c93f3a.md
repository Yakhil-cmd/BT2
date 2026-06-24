Audit Report

## Title
Stale Voting Power Snapshot Allows Dissolved Neurons to Vote Under Spike Detection Path - (`rs/nns/governance/src/governance.rs`, `rs/nns/governance/src/governance/voting_power_snapshots.rs`)

## Summary

When the NNS governance canister detects a voting power spike at proposal creation time, it creates ballots from a historical snapshot that can be up to 7 days old. The `register_vote` function performs no re-validation of current neuron eligibility at vote time. The code's own comment at the `register_vote` preconditions explicitly states the safety assumption — that dissolved neurons cannot vote because the minimum dissolve delay exceeds the maximum voting period — but this assumption is broken in the spike detection path, where the effective minimum dissolve delay at ballot creation time is reduced by the snapshot's age.

## Finding Description

**Ballot creation (spike path):**
In `rs/nns/governance/src/governance.rs` lines 5504–5524, when a spike is detected, ballots are created from the snapshot with minimum total potential voting power among the last 7 daily snapshots. This snapshot can be up to 7 days old (`MAX_VOTING_POWER_SNAPSHOTS = 7` in `voting_power_snapshots.rs` line 17).

**`register_vote` eligibility checks:**
In `rs/nns/governance/src/governance.rs` lines 5585–5672, the function checks only: (1) caller authorization, (2) proposal open for voting, (3) ballot presence in `proposal.ballots`, (4) ballot not already cast. There is no check of the neuron's current dissolve delay, stake, or activity status.

**The broken assumption:**
The comment at lines 5581–5584 states:
> "Practically, neurons that have already dissolved cannot vote, as long as the minimal possible dissolve delay is greater than the maximum possible voting period."

This holds in the normal path (ballots from current snapshot): minimum dissolve delay = 14 days (under Mission 70, `NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS_BOUNDS` lower bound at `network_economics.rs` line 293) > maximum NNS voting period ≈ 8 days (4-day initial + 4-day wait-for-quiet extension).

In the spike path, the snapshot can be 7 days old. A neuron with exactly 14 days dissolve delay at snapshot time has only 7 days remaining at proposal creation. Since 7 < 8 (maximum voting period), the neuron can dissolve during the voting period while still holding a valid ballot. The `previous_ballots_timestamp_seconds` field on `ProposalData` records the spike event but no runtime guard in `register_vote` acts on it.

**Snapshot filtering at capture time:**
`rs/nns/governance/src/neuron_store/voting_power.rs` lines 144–159 filters by `is_inactive` and `dissolve_delay_seconds >= min_dissolve_delay_seconds` only at snapshot time, not at vote time.

## Impact Explanation

A neuron owner whose neuron was eligible at snapshot time but has since dissolved (dissolve delay reached 0) can cast a vote on an open NNS proposal with the voting power recorded in the stale snapshot. The neuron no longer has any stake committed to the network's long-term health, yet retains full ballot rights. This is a concrete NNS governance integrity violation: an ineligible principal influences proposal outcomes. This matches the allowed impact: **High — Significant NNS security impact with concrete protocol harm**, as governance decisions (including protocol upgrades, treasury actions, and parameter changes) can be influenced by principals who have exited their stake commitment.

## Likelihood Explanation

- The spike detection path requires current total voting power > 1.5× the minimum snapshot total — unusual but demonstrated by the existing integration test `test_proposal_with_voting_power_spike`.
- Under Mission 70 (`MISSION_70_DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS = 14 * ONE_DAY_SECONDS`), the exploit window opens: a neuron with exactly 14 days dissolve delay at a 7-day-old snapshot has 7 days remaining at proposal creation, and can dissolve within the ≤8-day voting period.
- The attacker entry path is a standard unprivileged `manage_neuron` → `RegisterVote` ingress call.
- The attacker must have previously staked a neuron (realistic for any NNS participant).
- The 1-day exploitation window (T+7 to T+8) is tight but deterministic and controllable by the attacker who can time their `StartDissolving` call relative to the snapshot.

## Recommendation

In `register_vote` (`rs/nns/governance/src/governance.rs`), when `proposal.previous_ballots_timestamp_seconds` is `Some(_)` (indicating a spike-based ballot), add a runtime check that the neuron's current dissolve delay is ≥ `min_dissolve_delay_seconds` before accepting the vote. Alternatively, check that the neuron's current `deciding_voting_power` is non-zero. This restores the safety invariant the comment at lines 5581–5584 relies upon, specifically for the spike detection path where the invariant is otherwise violated.

## Proof of Concept

1. Run NNS for 7+ days with stable voting power to populate 7 daily snapshots.
2. Create a super-powerful neuron (e.g., 1,000,000 ICP) to trigger a spike (>1.5× minimum snapshot total).
3. Submit proposal P. Spike detected; ballots created from the 7-day-old snapshot. Neuron A (dissolve delay = 14 days at snapshot time, now 7 days remaining) receives a ballot.
4. Immediately call `StartDissolving` on Neuron A. It will reach dissolved state in 7 days.
5. Trigger wait-for-quiet extension (vote flip) to push the voting deadline to T+8.
6. At T+7 (after Neuron A dissolves), call `manage_neuron` → `RegisterVote` on proposal P with Neuron A.
7. `register_vote` finds Neuron A's ballot (`vote == Unspecified`), accepts the vote, and counts the full stale voting power — despite the neuron being dissolved and ineligible at vote time.

This can be implemented as a deterministic integration test extending `test_proposal_with_voting_power_spike` in `rs/nns/integration_tests/src/governance_proposals.rs`.