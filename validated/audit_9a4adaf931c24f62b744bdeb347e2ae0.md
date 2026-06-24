Audit Report

## Title
Missing Upper Bound on `disburse_maturity_in_progress` Vector Allows Unbounded Growth in SNS Governance - (File: `rs/sns/governance/src/governance.rs`)

## Summary
The SNS governance `disburse_maturity` function unconditionally appends to the `disburse_maturity_in_progress` vector on a neuron without enforcing any cap on concurrent entries. The NNS governance equivalent explicitly enforces `MAX_NUM_DISBURSEMENTS = 10` at the same logical point. The missing guard allows an authorized neuron controller to accumulate an arbitrarily large number of pending disbursement entries, bloating neuron state and degrading the `finalize_disburse_maturity` periodic timer.

## Finding Description
In `rs/sns/governance/src/governance.rs` at lines 1696–1698, after all validation passes, the function unconditionally pushes a new entry:

```rust
neuron
    .disburse_maturity_in_progress
    .push(disbursement_in_progress);
``` [1](#0-0) 

No check on `disburse_maturity_in_progress.len()` precedes this push. The only guards present are: (a) `percentage_to_disburse` must be 1–100, and (b) the worst-case modulated amount must exceed the transaction fee. Neither limits the number of concurrent entries.

By contrast, `rs/nns/governance/src/governance/disburse_maturity.rs` defines `MAX_NUM_DISBURSEMENTS = 10` and enforces it before pushing:

```rust
if num_disbursements >= MAX_NUM_DISBURSEMENTS {
    return Err(InitiateMaturityDisbursementError::TooManyDisbursements);
}
``` [2](#0-1) [3](#0-2) 

The `disburse_maturity_in_progress` field is a `repeated` protobuf field stored inline in the neuron's serialized state: [4](#0-3) 

The finalization timer calls `remove(0)` on the vector after each successful transfer, which is O(n) on a Rust `Vec`: [5](#0-4) 

## Impact Explanation
This matches the **High** bounty impact: "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS." An attacker with sufficient maturity can accumulate up to ~100 entries per neuron (bounded by maturity depletion at 1% per call). With multiple neurons or over time as maturity re-accrues from voting rewards, the total pending entries across the SNS governance canister grows. Each `remove(0)` in the finalization timer is O(n) per entry, and the timer iterates all neurons with pending disbursements. A sufficiently bloated state can cause the timer to exhaust its instruction budget and fail to make progress, stalling all maturity disbursements for all users of the SNS. Additionally, every neuron read/write incurs increased serialization cost proportional to the vector size.

## Likelihood Explanation
Any SNS neuron controller who has earned voting rewards (maturity) can trigger this via the standard `manage_neuron { DisburseMaturity { percentage_to_disburse: 1 } }` ingress call. No privileged access is required beyond holding a neuron with maturity. The minimum disbursement check limits the rate but does not prevent accumulation over time. This is reachable on any SNS with active voting rewards.

## Recommendation
Add a length guard in `Governance::disburse_maturity` before the push, mirroring the NNS pattern:

```rust
const MAX_DISBURSE_MATURITY_IN_PROGRESS: usize = 10;

if neuron.disburse_maturity_in_progress.len() >= MAX_DISBURSE_MATURITY_IN_PROGRESS {
    return Err(GovernanceError::new_with_message(
        ErrorType::PreconditionFailed,
        "Too many maturity disbursements in progress.",
    ));
}
```

This should be inserted after the mutable re-borrow of the neuron at line 1692 and before the `push` at line 1698. [6](#0-5) 

## Proof of Concept
1. Deploy a local SNS with a neuron holding sufficient maturity (e.g., 10,000 e8s equivalent).
2. As the neuron controller, call `manage_neuron { DisburseMaturity { percentage_to_disburse: 1 } }` repeatedly until the minimum disbursement check rejects further calls.
3. Inspect `neuron.disburse_maturity_in_progress.len()` — it grows with each call, with no rejection based on count.
4. Confirm the NNS equivalent rejects at 10 entries via `TooManyDisbursements`.
5. With many entries accumulated, observe that the `finalize_disburse_maturity` periodic task consumes proportionally more instructions per run due to O(n) `remove(0)` calls, verifiable via instruction metering in a PocketIC integration test.

### Citations

**File:** rs/sns/governance/src/governance.rs (L1692-1698)
```rust
        let neuron = self.get_neuron_result_mut(id)?;
        neuron.maturity_e8s_equivalent = neuron
            .maturity_e8s_equivalent
            .saturating_sub(maturity_to_deduct);
        neuron
            .disburse_maturity_in_progress
            .push(disbursement_in_progress);
```

**File:** rs/sns/governance/src/governance.rs (L5069-5069)
```rust
                    neuron.disburse_maturity_in_progress.remove(0);
```

**File:** rs/nns/governance/src/governance/disburse_maturity.rs (L40-40)
```rust
const MAX_NUM_DISBURSEMENTS: usize = 10;
```

**File:** rs/nns/governance/src/governance/disburse_maturity.rs (L306-308)
```rust
    if num_disbursements >= MAX_NUM_DISBURSEMENTS {
        return Err(InitiateMaturityDisbursementError::TooManyDisbursements);
    }
```

**File:** rs/sns/governance/proto/ic_sns_governance/pb/v1/governance.proto (L236-240)
```text
  // Disburse maturity operations that are currently underway.
  // The entries are sorted by `timestamp_of_disbursement_seconds`-values,
  // with the oldest entries first, i.e. it holds for all i that:
  // entry[i].timestamp_of_disbursement_seconds <= entry[i+1].timestamp_of_disbursement_seconds
  repeated DisburseMaturityInProgress disburse_maturity_in_progress = 18;
```
