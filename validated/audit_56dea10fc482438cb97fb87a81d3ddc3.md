Audit Report

## Title
Build/Validate Asymmetry: `FlexibleCanisterHttpError::Timeout` Counted by `num_non_timeout_responses()` but Excluded from `responses_included` During Build — (`rs/types/types/src/batch/canister_http.rs`, `rs/https_outcalls/consensus/src/payload_builder.rs`)

## Summary

During payload building, `FlexibleCanisterHttpError::Timeout` entries are pushed into `flexible_errors` and the loop `continue`s before incrementing `responses_included`, intentionally bypassing the `CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK` (500) limit. During validation, `num_non_timeout_responses()` adds `flexible_errors.len()` unconditionally — including `Timeout` variants — against that same limit. A payload legitimately built with >500 flexible timeouts will fail its own validation with `TooManyResponses`, stalling subnet progress.

## Finding Description

**Build path** (`get_canister_http_payload_impl`, `rs/https_outcalls/consensus/src/payload_builder.rs`):

When a flexible request has timed out, a `FlexibleCanisterHttpError::Timeout` is pushed to `flexible_errors` and the loop `continue`s at line 256, skipping the `responses_included` increment entirely. The comment at lines 235–237 explicitly states timeouts are "not counted as responses" and are "irrelevant for the `CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK` limit." [1](#0-0) 

The only cap on flexible timeout entries is the 2 MiB `max_payload_size`. Since `FlexibleCanisterHttpError::Timeout` is just a `CallbackId` (8 bytes), 501 entries occupy ~4 KB — well within the limit.

**Validation path** (`validate_canister_http_payload_impl`):

The check at line 380 calls `num_non_timeout_responses()`: [2](#0-1) 

`num_non_timeout_responses()` correctly excludes the `timeouts` field via `timeouts: _`, but unconditionally adds `flexible_errors.len()` with no match/filter to exclude the `Timeout` arm: [3](#0-2) 

`FlexibleCanisterHttpError` has three variants — `Timeout`, `ResponsesTooLarge`, and `TooManyRejects` — and only `Timeout` should be excluded from the count, mirroring how the regular `timeouts` vec is handled: [4](#0-3) 

**Gap in test coverage:** The existing test `timeouts_bypass_max_responses_per_block` uses `fully_replicated_contexts` (non-flexible), so it exercises only the `timeouts` vec path and does not catch this asymmetry: [5](#0-4) 

## Impact Explanation

When >500 flexible HTTP requests time out simultaneously, every block proposer builds a payload containing 501+ `FlexibleCanisterHttpError::Timeout` entries in `flexible_errors`. The proposer then validates its own payload; `num_non_timeout_responses()` returns 501+ → `TooManyResponses` → the block is rejected. Because the timed-out request contexts remain in state until a block delivers them, and no block can be finalized while this condition persists, the subnet stalls for every round until the condition is resolved externally. This matches the allowed impact: **High — Application/platform-level DoS / subnet availability impact not based on raw volumetric DDoS** ($2,000–$10,000).

## Likelihood Explanation

- Requires the Flexible HTTP feature to be enabled on the target subnet.
- Requires an attacker canister to submit >500 flexible HTTP requests and wait for `CANISTER_HTTP_TIMEOUT_INTERVAL` to elapse with no responses.
- No privileged access, no key material, no majority corruption needed.
- The attacker pays cycles for the requests, but the cost is bounded and one-time.
- Triggerable by any unprivileged canister developer on an affected subnet.

## Recommendation

Fix `num_non_timeout_responses()` to exclude `FlexibleCanisterHttpError::Timeout` variants from the count, mirroring how the regular `timeouts` field is already excluded:

```rust
pub fn num_non_timeout_responses(&self) -> usize {
    let CanisterHttpPayload {
        responses,
        timeouts: _,
        divergence_responses,
        flexible_responses,
        flexible_errors,
    } = self;
    responses.len()
        + divergence_responses.len()
        + flexible_responses.len()
        + flexible_errors
            .iter()
            .filter(|e| !matches!(e, FlexibleCanisterHttpError::Timeout { .. }))
            .count()
}
```

This restores build/validate symmetry: flexible timeouts are free in both paths.

## Proof of Concept

1. Enable Flexible HTTP on a test subnet.
2. Inject 501 `CanisterHttpRequestContext` entries with `Replication::Flexible`, all with `time = UNIX_EPOCH` (so they are past `CANISTER_HTTP_TIMEOUT_INTERVAL`).
3. Call `build_payload` with a `validation_context.time` past the timeout interval.
4. Parse the resulting bytes → assert `flexible_errors.len() == 501`, assert all entries have variant `Timeout`.
5. Call `validate_payload` on the same bytes.
6. Assert: validation returns `Err(TooManyResponses { received: 501 })`. Expected: `Ok(())`.

An analogous test to `timeouts_bypass_max_responses_per_block` using `Replication::Flexible` contexts (instead of `fully_replicated_contexts`) would reproduce the failure deterministically. [5](#0-4)

### Citations

**File:** rs/https_outcalls/consensus/src/payload_builder.rs (L234-256)
```rust
                if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL < validation_context.time {
                    // Because timeouts are very cheap to verify, they are
                    // not counted as responses (so that they are irrelevant
                    // for the CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK limit.
                    if matches!(request.replication, Replication::Flexible { .. }) {
                        let error = FlexibleCanisterHttpError::Timeout {
                            callback_id: *callback_id,
                        };
                        let candidate_size = error.count_bytes();
                        let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                        if size < max_payload_size {
                            flexible_errors.push(error);
                            accumulated_size += candidate_size;
                        }
                    } else {
                        let candidate_size = callback_id.count_bytes();
                        let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                        if size < max_payload_size {
                            timeouts.push(*callback_id);
                            accumulated_size += candidate_size;
                        }
                    }
                    continue;
```

**File:** rs/https_outcalls/consensus/src/payload_builder.rs (L379-385)
```rust
        // Check number of responses
        if payload.num_non_timeout_responses() > CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
            return invalid_artifact(InvalidCanisterHttpPayloadReason::TooManyResponses {
                expected: CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK,
                received: payload.num_non_timeout_responses(),
            });
        }
```

**File:** rs/types/types/src/batch/canister_http.rs (L44-58)
```rust
pub enum FlexibleCanisterHttpError {
    Timeout {
        callback_id: CallbackId,
    },
    ResponsesTooLarge {
        callback_id: CallbackId,
        all_seen_shares: Vec<CanisterHttpResponseShare>,
        total_requests: u32,
        min_responses: u32,
    },
    TooManyRejects {
        callback_id: CallbackId,
        reject_responses: Vec<FlexibleCanisterHttpResponseWithProof>,
    },
}
```

**File:** rs/types/types/src/batch/canister_http.rs (L165-178)
```rust
    /// Returns the number of non_timeout responses
    pub fn num_non_timeout_responses(&self) -> usize {
        let CanisterHttpPayload {
            responses,
            timeouts: _,
            divergence_responses,
            flexible_responses,
            flexible_errors,
        } = self;
        responses.len()
            + divergence_responses.len()
            + flexible_responses.len()
            + flexible_errors.len()
    }
```

**File:** rs/https_outcalls/consensus/src/payload_builder/tests.rs (L383-431)
```rust
/// Timeouts must not count against CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK.
/// Create MAX + 50 timed-out request contexts. The builder should include
/// all of them, and the resulting payload must pass validation.
#[test]
fn timeouts_bypass_max_responses_per_block() {
    let subnet_size = 4;
    let num_contexts = CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK + 50;

    test_config_with_http_feature(
        true,
        subnet_size,
        |mut payload_builder, _canister_http_pool| {
            let callback_ids = 0..num_contexts as u64;

            let contexts = fully_replicated_contexts(callback_ids.clone());
            inject_request_contexts(&mut payload_builder, contexts);

            // The contexts created above use the default time = UNIX_EPOCH, so any
            // validation time beyond UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL
            // makes those contexts time out.
            let validation_context = ValidationContext {
                registry_version: RegistryVersion::new(1),
                certified_height: Height::new(0),
                time: UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL + Duration::from_secs(1),
            };

            let payload = payload_builder.build_payload(
                Height::new(1),
                TEST_MAX_PAYLOAD_BYTES,
                &[],
                &validation_context,
            );

            let parsed = bytes_to_payload(&payload).expect("Failed to parse payload");

            assert_eq!(parsed.num_non_timeout_responses(), 0);
            assert_eq!(parsed.timeouts.len(), num_contexts);

            payload_builder
                .validate_payload(
                    Height::new(1),
                    &test_proposal_context(&validation_context),
                    &payload,
                    &[],
                )
                .unwrap();
        },
    );
}
```
