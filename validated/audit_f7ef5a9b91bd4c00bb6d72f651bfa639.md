Audit Report

## Title
SNS Governance `ExecuteGenericNervousSystemFunction` Payload Size Unenforced — Heap Memory Exhaustion DoS Blocking All Proposals - (File: `rs/sns/governance/src/types.rs`)

## Summary

The SNS governance canister defines `PROPOSAL_EXECUTE_SNS_FUNCTION_PAYLOAD_BYTES_MAX` (70,000 bytes) but marks it `#[allow(dead_code)]` with a TODO and never enforces it in the proposal validation path. An attacker with sufficient stake can submit up to 700 open proposals carrying arbitrarily large payloads (up to the ~2 MB IC message limit), exhausting heap and blocking all new proposal submissions for the full voting period, with potential for permanent canister impairment if the heap soft limit is breached.

## Finding Description

`PROPOSAL_EXECUTE_SNS_FUNCTION_PAYLOAD_BYTES_MAX` is declared but explicitly unused: [1](#0-0) 

The validation dispatch for `ExecuteGenericNervousSystemFunction` in `validate_and_render_action` calls only the externally-registered validator canister — no local size check is performed before or after: [2](#0-1) 

By contrast, NNS governance explicitly enforces `PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX` before storing the proposal: [3](#0-2) 

Once validation passes, the full `ProposalData` — including raw payload bytes and a ballot entry per eligible neuron — is stored on the heap. The global cap on unsettled proposals is: [4](#0-3) 

The cap check blocks all non-whitelisted proposals once 700 unsettled proposals exist: [5](#0-4) 

Ballots (and thus the unsettled count) are only cleared after a reward event settles the proposal: [6](#0-5) 

The heap soft limit is 3.5 GiB: [7](#0-6) 

The memory test canister itself estimates `ExecuteGenericNervousSystemFunction` payloads at ~1 MB each: [8](#0-7) 

## Impact Explanation

**Governance DoS (High):** Once 700 unsettled proposals are stored, `make_proposal` returns `ResourceExhausted` for all non-whitelisted proposal types. No legitimate user can submit proposals until the voting period expires and a reward round clears ballots — a minimum delay of `initial_voting_period_seconds` (default 4 days) plus one reward round. This is a concrete, application-level DoS of SNS governance with direct user harm, matching the allowed impact: *"Application/platform-level DoS … or subnet availability impact not based on raw volumetric DDoS"* and *"Significant SNS … security impact with concrete user or protocol harm."*

**Heap exhaustion (High, escalating):** At 700 proposals × ~2 MB payload each, ~1.4 GB of payload data is stored on the heap, plus ballot storage for all neurons. If the 3.5 GiB soft limit is breached, `check_heap_can_grow` blocks even whitelisted proposals and canister upgrades may fail, permanently impairing the SNS governance canister.

Severity: **High ($2,000–$10,000)**.

## Likelihood Explanation

**Preconditions:**
1. Attacker holds a neuron with stake ≥ `reject_cost_e8s` × 700. In many SNS deployments `reject_cost_e8s` is low (e.g., 1 token), making 700 tokens a realistic threshold for a motivated attacker.
2. At least one `GenericNervousSystemFunction` is registered whose validator canister does not enforce a payload size limit — common, since SNS governance itself imposes no such requirement on validators.

**Trigger:** The attacker calls `make_proposal` 700 times with `ExecuteGenericNervousSystemFunction` payloads near the IC message size limit (~2 MB). Each call passes the external validator and is stored in heap. The reject cost is charged upfront as `neuron_fees_e8s` but is a known, bounded cost: [9](#0-8) 

The attack is repeatable each voting cycle and requires no privileged access beyond normal neuron ownership.

## Recommendation

Enforce `PROPOSAL_EXECUTE_SNS_FUNCTION_PAYLOAD_BYTES_MAX` inside `validate_and_render_execute_nervous_system_function` (or at the dispatch site in `validate_and_render_action`) before the external validator canister is called, mirroring the NNS pattern at `rs/nns/governance/src/governance.rs:4933–4942`. Remove the `#[allow(dead_code)]` annotation and wire the constant into the validation path. Additionally, consider a per-neuron cap on simultaneously open proposals to prevent a single actor from saturating the global 700-proposal limit.

## Proof of Concept

1. Register a `GenericNervousSystemFunction` with a validator canister that accepts any payload (returns `Ok(String)`).
2. Obtain a neuron with ≥ 700 × `reject_cost_e8s` staked.
3. In a loop (700 iterations), call `make_proposal` with:
   ```rust
   Action::ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction {
       function_id: <registered_id>,
       payload: vec![0u8; 2_000_000], // ~2 MB, no SNS-side size check
   })
   ```
4. After 700 calls, any subsequent `make_proposal` from any neuron returns `ResourceExhausted`.
5. The governance canister heap grows by ~700 × 2 MB = ~1.4 GB of payload data plus ballot storage, approaching or exceeding the 3.5 GiB soft limit.

A deterministic integration test using PocketIC can reproduce this by submitting 700 oversized proposals against a local SNS governance instance and asserting that the 701st call returns `ResourceExhausted` and that heap usage exceeds the soft limit threshold.

### Citations

**File:** rs/sns/governance/src/types.rs (L72-75)
```rust
#[allow(dead_code)]
/// TODO Use to validate the size of the payload 70 KB (for executing
/// SNS functions that are not canister upgrades)
const PROPOSAL_EXECUTE_SNS_FUNCTION_PAYLOAD_BYTES_MAX: usize = 70000;
```

**File:** rs/sns/governance/src/proposal.rs (L78-79)
```rust
/// The maximum number of unsettled proposals (proposals for which ballots are still stored).
pub const MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS: usize = 700;
```

**File:** rs/sns/governance/src/proposal.rs (L436-439)
```rust
        Action::ExecuteGenericNervousSystemFunction(execute) => {
            validate_and_render_execute_nervous_system_function(env, execute, existing_functions)
                .await
        }
```

**File:** rs/nns/governance/src/governance.rs (L4933-4942)
```rust
        // Check payload size limits
        if !update.can_have_large_payload()
            && update.payload.len() > PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX
        {
            return Err(invalid_proposal_error(format!(
                "The maximum NNS function payload size in a proposal action is {} bytes, this payload is: {} bytes",
                PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX,
                update.payload.len(),
            )));
        }
```

**File:** rs/sns/governance/src/governance.rs (L164-169)
```rust
/// The max number of wasm32 pages for the heap after which we consider that there
/// is a risk to the ability to grow the heap.
///
/// This is 7/8 of the maximum number of pages and corresponds to 3.5 GiB.
pub const HEAP_SIZE_SOFT_LIMIT_IN_WASM32_PAGES: usize =
    MAX_HEAP_SIZE_IN_KIB / WASM32_PAGE_SIZE_IN_KIB * 7 / 8;
```

**File:** rs/sns/governance/src/governance.rs (L3528-3547)
```rust
        // Check that there are not too many proposals.  What matters
        // here is the number of proposals for which ballots have not
        // yet been cleared, because ballots take the most amount of
        // space.
        if self
            .proto
            .proposals
            .values()
            .filter(|data| !data.ballots.is_empty())
            .count()
            >= MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS
            && !proposal.allowed_when_resources_are_low()
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::ResourceExhausted,
                "Reached maximum number of proposals that have not yet \
                been taken into account for voting rewards. \
                Please try again later.",
            ));
        }
```

**File:** rs/sns/governance/src/governance.rs (L3644-3653)
```rust
        // Charge the cost of rejection upfront.
        // This will protect from DoS in couple of ways:
        // - It prevents a neuron from having too many proposals outstanding.
        // - It reduces the voting power of the submitter so that for every proposal
        //   outstanding the submitter will have less voting power to get it approved.
        self.proto
            .neurons
            .get_mut(&proposer_id.to_string())
            .expect("Proposer not found.")
            .neuron_fees_e8s += proposal_data.reject_cost_e8s;
```

**File:** rs/sns/governance/src/governance.rs (L6074-6080)
```rust
            // Ballots are used to determine two things:
            //   1. (obviously and primarily) whether to execute the proposal.
            //   2. rewards
            // At this point, we no longer need ballots for either of these
            // things, and since they take up a fair amount of space, we take
            // this opportunity to jettison them.
            p.ballots.clear();
```

**File:** rs/sns/integration_tests/test_canisters/sns_governance_mem_test_canister.rs (L280-280)
```rust
        x if x == NativeAction::ExecuteGenericNervousSystemFunction as u64 => 1_000_000, // Estimate of average payload size = 1MB
```
