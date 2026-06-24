Audit Report

## Title
Cycles Conservation Violation: `PricingFactory::new_tracker` Always Creates `LegacyTracker`, Causing Permanent Cycles Loss for `FlexibleHttpRequest` (PayAsYouGo) Callers — (`rs/https_outcalls/pricing/src/lib.rs`)

## Summary
`PricingFactory::new_tracker` unconditionally creates a `LegacyTracker` regardless of `context.pricing_version`. For `FlexibleHttpRequest` calls using `PricingVersion::PayAsYouGo`, the execution environment takes the caller's entire payment upfront and records a non-zero `refundable_cycles`. However, because the adapter always uses `LegacyTracker`, every per-replica `CanisterHttpPaymentReceipt` carries `refund = 0`. The adapter also immediately rejects all `PayAsYouGo` requests with `SysFatal`. The net result is that the caller's cycles above `base_fee` are permanently destroyed with no service rendered.

## Finding Description

**Step 1 — Execution environment takes full payment upfront for PayAsYouGo.**

In `rs/execution_environment/src/execution_environment.rs` at `try_add_http_context_to_replicated_state`, lines 2189–2219:

```rust
let refundable_cycles = if cost_schedule == CanisterCyclesCostSchedule::Free {
    Cycles::new(0)
} else {
    canister_http_request_context.request.payment - base_fee.real()
};
// ...
canister_http_request_context.refund_status = RefundStatus {
    refundable_cycles,
    per_replica_allowance: refundable_cycles / node_count,
    ...
};
// PayAsYouGo: take out the entire payment upfront
if cost_schedule != CanisterCyclesCostSchedule::Free {
    canister_http_request_context.request.payment.take();
}
```

`request.payment` is zeroed; `refundable_cycles = original_payment - base_fee` is stored in `refund_status` to be returned via per-replica receipts.

**Step 2 — `PricingFactory::new_tracker` ignores `pricing_version` and always creates `LegacyTracker`.**

`rs/https_outcalls/pricing/src/lib.rs` lines 55–60:

```rust
pub fn new_tracker(context: &CanisterHttpRequestContext) -> Box<dyn BudgetTracker> {
    // TODO(IC-1937): This should take into account context.pricing_version and a replica config.
    // Currently, we only support the legacy pricing version.
    Box::new(LegacyTracker::new(context.max_response_bytes))
}
```

The `TODO(IC-1937)` comment confirms this is a known incomplete implementation.

**Step 3 — `LegacyTracker::create_payment_receipt()` always returns `refund = 0`.**

`rs/https_outcalls/pricing/src/legacy.rs` lines 48–52:

```rust
fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt {
    // Legacy pricing does not perform cycles accounting, so no cycles
    // are ever refunded.
    CanisterHttpPaymentReceipt::default()
}
```

**Step 4 — The adapter client explicitly rejects PayAsYouGo requests with `SysFatal` and sends the zero-refund receipt.**

`rs/https_outcalls/client/src/client.rs` lines 155–178:

```rust
if request_pricing_version == ic_types::canister_http::PricingVersion::PayAsYouGo {
    let _ = permit.send((
        CanisterHttpResponse { ... SysFatal reject ... },
        budget.create_payment_receipt(),  // refund = 0
    ));
    return;
}
```

**Step 5 — `check_refund_allowance` passes silently.**

`rs/https_outcalls/consensus/src/payload_builder/utils.rs` lines 81–92: the check only rejects if `receipt.refund > per_replica_allowance`. Since `receipt.refund = 0`, the check always passes regardless of how large `per_replica_allowance` is.

**Net result:** Caller paid `P` cycles. `base_fee` is legitimately consumed. `P - base_fee` is stored as `refundable_cycles` but `request.payment` is zeroed. The per-replica receipt carries `refund = 0`. Consensus accepts it. The caller receives a `SysFatal` reject and `msg_cycles_refunded() = 0`. The `P - base_fee` cycles are permanently destroyed.

The `ALLOWED_HTTP_OUTCALLS_PRICING_VERSIONS` constant (`rs/types/management_canister_types/src/http.rs` line 72) restricts the regular `HttpRequest` endpoint to `PRICING_VERSION_LEGACY` only, so `FlexibleHttpRequest` is the sole path to `PayAsYouGo` pricing.

## Impact Explanation

Any canister invoking `FlexibleHttpRequest` on a subnet where the feature is enabled loses all cycles above `base_fee` permanently per request, with no service rendered. This is a cycles conservation violation: cycles are destroyed without providing the corresponding service. This matches the allowed ICP bounty impact of **permanent loss of cycles** (Medium, $200–$2,000), constrained by the requirement that the `FlexibleHttpRequest` feature flag be enabled on the target subnet.

## Likelihood Explanation

The attack requires `FlexibleHttpRequest` to be enabled on an application subnet (controlled by subnet configuration in `rs/config/src/execution_environment.rs`). If enabled, any unprivileged canister caller can trigger the bug with a single call to `FlexibleHttpRequest` with any payment above `base_fee`. No special privileges, social engineering, or protocol-level access is required. The `TODO(IC-1937)` comment confirms this is a known incomplete implementation, not an intentional design choice. The bug is repeatable and deterministic.

## Recommendation

`PricingFactory::new_tracker` must branch on `context.pricing_version`:

```rust
pub fn new_tracker(context: &CanisterHttpRequestContext) -> Box<dyn BudgetTracker> {
    match context.pricing_version {
        PricingVersion::Legacy => Box::new(LegacyTracker::new(context.max_response_bytes)),
        PricingVersion::PayAsYouGo => Box::new(PayAsYouGoTracker::new(
            context.refund_status.per_replica_allowance,
        )),
    }
}
```

Until a `PayAsYouGoTracker` is implemented, `FlexibleHttpRequest` should either be disabled at the subnet configuration level, or the execution environment should not zero `request.payment` for `PayAsYouGo` requests that will be rejected by the adapter (i.e., defer the upfront deduction until the adapter confirms support).

## Proof of Concept

1. Deploy a canister on a subnet with `FlexibleHttpRequest` enabled.
2. Call `FlexibleHttpRequest` with payment `P = 1_000_000_000` cycles.
3. Execution environment: `request.payment.take()` → 0; `refundable_cycles = P - base_fee` stored in `refund_status`.
4. Adapter: `PricingFactory::new_tracker` creates `LegacyTracker`; returns `SysFatal` reject with `payment_receipt.refund = 0`.
5. Consensus: `check_refund_allowance(0, per_replica_allowance)` passes (0 ≤ per_replica_allowance).
6. Response delivered to canister: `msg_cycles_refunded() = 0`.
7. Canister has lost `P - base_fee` cycles with no service rendered.

A deterministic integration test can reproduce this by constructing a `CanisterHttpRequestContext` with `pricing_version = PayAsYouGo`, a non-zero payment, calling `try_add_http_context_to_replicated_state`, then simulating the adapter response path through `CanisterHttpAdapterClientImpl` and asserting that `payment_receipt.refund == 0` while `refund_status.refundable_cycles > 0`.