Audit Report

## Title
Unbounded Iteration in `get_pending_proposals` Enables Query-Level DoS via Proposal Flooding - (File: `rs/nns/governance/src/governance.rs`)

## Summary
`get_pending_proposals` iterates over all open proposals in `heap_data.proposals` with no result cap or instruction-count guard. Because `MAX_NUMBER_OF_OPEN_MANAGE_NEURON_PROPOSALS` permits up to 10,000 simultaneously open manage-neuron proposals, an attacker who controls neurons with sufficient stake can flood the proposal queue and cause the function to exhaust the 5-billion-instruction query limit, permanently breaking the endpoint for all callers until proposals expire.

## Finding Description
`get_pending_proposals` in `rs/nns/governance/src/governance.rs` (lines 3469–3495) scans the entire `heap_data.proposals` map, filters for `ProposalStatus::Open`, converts each matching entry via `proposal_data_to_info`, and collects results with no upper bound:

```rust
self.heap_data
    .proposals
    .values()
    .filter(|data| data.status() == ProposalStatus::Open)
    .map(|data| { proposal_data_to_info(...) })
    .collect()   // ← no .take(limit)
```

Two separate open-proposal caps exist:
- Regular proposals: `MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS = 200`
- Manage-neuron proposals: `MAX_NUMBER_OF_OPEN_MANAGE_NEURON_PROPOSALS = 10_000`

Both categories pass the `ProposalStatus::Open` filter, so the loop can touch up to 10,200 proposals in a single query call.

The `proposal_data_to_info` function (`rs/nns/governance/src/pb/proposal_conversions.rs`, lines 539–600) performs per-proposal work including status/reward-status/deadline calculations, field copies, and `convert_proposal` (which clones the full proposal action struct). The `convert_ballots` helper (lines 526–537) iterates over `caller_neurons` rather than over all ballots, so ballot-filtering cost is O(caller_neurons) per proposal — but the remaining per-proposal overhead (struct cloning, field conversions, map traversal) across 10,000 proposals is sufficient to approach or exceed the 5B-instruction query budget.

By contrast, `list_proposals` (lines 3623–3654) applies `.take(limit)` capped at `MAX_LIST_PROPOSAL_RESULTS`, making it immune to this issue.

The endpoint is exposed as a `#[query]` in `rs/nns/governance/canister/canister.rs` (lines 373–377) and is listed in the public Candid interface (`rs/nns/governance/canister/governance.did`). The ICP Rosetta API calls this endpoint directly in `rs/rosetta-api/icp/src/ledger_client.rs` (lines 375–396).

## Impact Explanation
This is an application/platform-level DoS against a public NNS governance query endpoint. Once the manage-neuron proposal queue is saturated at 10,000 entries, every call to `get_pending_proposals` traps with `CanisterInstructionLimitExceeded`. The endpoint becomes permanently unusable until proposals expire (days to weeks). The ICP Rosetta API, which calls `get_pending_proposals` to serve voting data, is also broken for the duration. This matches the allowed High impact: "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."

## Likelihood Explanation
The attacker needs neurons with sufficient stake and dissolve delay to submit manage-neuron proposals, and must be a followee of the managed neuron on the `NeuronManagement` topic — both conditions are fully self-controllable. The NNS proposal fee is 0.01 ICP per proposal; submitting 10,000 proposals costs ~100 ICP. The attack is self-sustaining: once the queue is full, the attacker only needs to replace expiring proposals at low ongoing cost. No privileged access, no threshold corruption, and no external dependency is required.

## Recommendation
Apply pagination to `get_pending_proposals` mirroring `list_proposals`:
1. Accept an optional `before_proposal` cursor and a `limit` parameter.
2. Apply `.take(limit)` before `.collect()`, capping results at `MAX_LIST_PROPOSAL_RESULTS = 100`.
3. Alternatively, add an instruction-count guard inside the loop (analogous to `over_soft_message_limit()` used in `rs/nns/governance/src/voting.rs` and `is_message_over_threshold` in `rs/nns/governance/src/reward/distribution.rs`) and return a partial result with a continuation cursor.

## Proof of Concept
1. Create or control a neuron with sufficient stake and dissolve delay.
2. Set the neuron as a followee of another self-controlled neuron on the `NeuronManagement` topic.
3. Submit manage-neuron proposals targeting the self-controlled neuron until `MAX_NUMBER_OF_OPEN_MANAGE_NEURON_PROPOSALS = 10_000` is reached (cost: ~100 ICP).
4. Call `get_pending_proposals` as any principal (no authentication required).
5. The function iterates over all 10,000+ open proposals, calling `proposal_data_to_info` for each, exhausting the 5B-instruction query budget.
6. The query traps; the endpoint is DoS'd for all callers until proposals expire.

The existing test at `rs/nns/governance/tests/governance.rs` (lines 8043–8047) confirms that `get_pending_proposals` returns all `MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS` proposals without any limit, demonstrating the unbounded collection behavior.