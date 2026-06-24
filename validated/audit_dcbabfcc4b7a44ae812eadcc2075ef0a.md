Audit Report

## Title
SNS Swap Auto-Finalization Permanently Blocked by Any Transient External Canister Error - (File: rs/sns/swap/src/swap.rs)

## Summary
`try_auto_finalize` sets `already_tried_to_auto_finalize = Some(true)` at line 719 unconditionally before invoking `finalize` at line 722. If any of the chained external canister calls inside `finalize_inner` returns a transient error, the one-shot guard is already committed, and `can_auto_finalize` will permanently reject all future automatic attempts. Participants' ICP and SNS tokens remain locked in the swap canister and SNS governance stays in pre-initialization mode until a human operator manually calls `finalize_swap`.

## Finding Description
In `rs/sns/swap/src/swap.rs`, `try_auto_finalize` (line 704) first calls `can_auto_finalize()` to confirm the attempt is allowed, then immediately sets the permanent guard at line 719 before any external I/O:

```rust
self.already_tried_to_auto_finalize = Some(true);   // line 719
let auto_finalize_swap_response = self.finalize(now_fn, environment).await;  // line 722
```

`finalize` delegates to `finalize_inner` (line 1544), which chains at least six external canister calls in sequence, returning early on the first error:
1. `sweep_icp` → ICP ledger (lines 1557–1561)
2. `settle_neurons_fund_participation` → NNS governance (lines 1564–1570)
3. `sweep_sns` → SNS ledger (lines 1594–1598)
4. `claim_swap_neurons` → SNS governance (lines 1602–1608)
5. `set_sns_governance_to_normal_mode` → SNS governance (lines 1610–1612)
6. `take_sole_control_of_dapp_controllers_for_finalize` → SNS root (lines 1617–1620)

`can_auto_finalize` (line 2936) permanently gates all future automatic attempts:

```rust
if self.already_tried_to_auto_finalize.unwrap_or(true) {
    return Err(...)
}
```

Because the guard is set before any of these calls execute, a `SysTransient` rejection from any one of the six canisters (e.g., NNS governance mid-upgrade) causes `finalize_inner` to return early with an error, but the guard is already `Some(true)`. Every subsequent invocation of `run_periodic_tasks` reaches `can_auto_finalize().is_ok()` at line 1059, which now returns `Err`, and the auto-finalization branch is never re-entered. The log message at line 716 explicitly acknowledges this: *"Will not automatically attempt again even if this fails."*

No existing check distinguishes transient (`SysTransient`, reject code 2) from permanent errors before halting `finalize_inner` or before committing the guard.

## Impact Explanation
This is a **High** severity finding matching the allowed impact: *"Significant SNS… security impact with concrete user or protocol harm."* When triggered, all direct and Neurons' Fund participants have their ICP contributions locked in the swap canister's subaccounts, SNS tokens are not distributed, and SNS governance remains in pre-initialization mode (unable to accept proposals or operate normally). The state persists indefinitely until a human operator discovers the failure and manually calls `finalize_swap`. While manual recovery is possible, there is no on-chain alert, no automatic retry, and no time bound on the locked state.

## Likelihood Explanation
No attacker is required. The IC mainnet performs routine canister upgrades on a regular cadence. During an upgrade, a canister is temporarily stopped and any in-flight inter-canister call to it receives a `SysTransient` rejection. Because `finalize_inner` calls five or more distinct system canisters (ICP ledger, NNS governance, SNS ledger, SNS governance, SNS root), the probability that at least one is mid-upgrade during the single auto-finalization window is non-trivial, particularly for high-profile SNS launches that coincide with NNS upgrade proposals. The condition is fully deterministic once the timing overlap occurs and requires no privileged access.

## Recommendation
Move the `already_tried_to_auto_finalize = Some(true)` assignment to after `finalize` returns, and only set it when the response contains no error message (i.e., finalization fully succeeded). Alternatively, inspect `FinalizeSwapResponse.error_message` and only commit the flag permanently when the error is confirmed non-transient. A third option is to introduce a retry counter with a bounded maximum, resetting on transient errors and only permanently blocking after a non-transient failure or after exhausting retries.

## Proof of Concept
1. Deploy an SNS swap that reaches `Lifecycle::Committed` with `should_auto_finalize = true`.
2. Arrange for NNS governance (or any other target canister in the chain) to be mid-upgrade when `run_periodic_tasks` fires.
3. `run_periodic_tasks` calls `try_auto_finalize`; `already_tried_to_auto_finalize` is set to `Some(true)` at line 719.
4. `finalize_inner` calls `sweep_icp` successfully, then calls `settle_neurons_fund_participation`, which receives a `SysTransient` rejection from NNS governance.
5. `finalize_inner` sets `error_message` on `FinalizeSwapResponse` and returns early.
6. `try_auto_finalize` stores the failed response; `already_tried_to_auto_finalize` remains `Some(true)`.
7. All subsequent `run_periodic_tasks` invocations find `can_auto_finalize()` returning `Err`; the auto-finalization branch is never re-entered.
8. Participants' ICP and SNS tokens remain locked; SNS governance stays in pre-initialization mode until manual `finalize_swap` is called.

A deterministic integration test using PocketIC can reproduce this by injecting a `SysTransient` response from a mock NNS governance canister during the `settle_neurons_fund_participation` call and asserting that subsequent `run_periodic_tasks` invocations never re-attempt finalization.