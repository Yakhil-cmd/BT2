Audit Report

## Title
Build/Validate Asymmetry: `FlexibleCanisterHttpError::Timeout` Counted Against Response Limit During Validation But Not During Build — (`rs/types/types/src/batch/canister_http.rs`, `rs/https_outcalls/consensus/src/payload_builder.rs`)

## Summary

`num_non_timeout_responses()` unconditionally adds `flexible_errors.len()` to the response count, but `flexible_errors` can contain `FlexibleCanisterHttpError::Timeout` variants that the build path explicitly exempts from the `CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK` (500) limit. When more than 500 flexible HTTP requests time out simultaneously, every block proposer builds a payload that immediately fails its own validation with `TooManyResponses`, stalling subnet consensus until the condition is externally resolved.

## Finding Description

**Build path** (`payload_builder.rs`, lines 234–256): When a flexible request has timed out, a `FlexibleCanisterHttpError::Timeout` is pushed to `flexible_errors` and the loop `continue`s, bypassing the `responses_included` increment entirely. The comment explicitly states timeouts are "not counted as responses" and are "irrelevant for the `CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK` limit." The only cap is the 2 MiB `max_payload_size`; at 8 bytes per `CallbackId`, 501 entries occupy ~4 KB.

**Validation path** (`payload_builder.rs`, line 380): `validate_canister_http_payload_impl` calls `payload.num_non_timeout_responses()` and rejects with `TooManyResponses` if the result exceeds 500.

**Root cause** (`canister_http.rs`, lines 165–178): `num_non_timeout_responses()` correctly ignores the `timeouts` field via `timeouts: _`, but adds `flexible_errors.len()` without filtering — there is no match/filter to exclude the `FlexibleCanisterHttpError::Timeout` arm. `ResponsesTooLarge` and `TooManyRejects` variants in `flexible_errors` are legitimate non-timeout errors that should be counted; only `Timeout` should be excluded, mirroring the treatment of the `timeouts` vec.

**Exploit flow:**
1. Attacker canister submits 501+ flexible HTTP requests (all with `Replication::Flexible`).
2. Attacker waits for `CANISTER_HTTP_TIMEOUT_INTERVAL` to elapse with no responses delivered.
3. Every block proposer calls `get_canister_http_payload_impl`, which includes all 501+ `FlexibleCanisterHttpError::Timeout` entries in `flexible_errors` (no `responses_included` guard).
4. The proposer then calls `validate_canister_http_payload_impl` on its own payload.
5. `num_non_timeout_responses()` returns 501+ → `TooManyResponses` → block rejected.
6. The timed-out request contexts remain in state until a block delivers them; no block can be finalized while this condition persists.

**Existing test gap:** The test `timeouts_bypass_max_responses_per_block` (tests.rs, lines 383–431) uses `fully_replicated_contexts`, which produces entries in the `timeouts` vec (correctly excluded). No analogous test exists for `Replication::Flexible` contexts, leaving the asymmetry undetected.

## Impact Explanation

This is a **consensus-blocking subnet availability impact** triggered without any privileged access. The subnet stalls for every consensus round while 501+ flexible timeout contexts remain undelivered in state. This matches the High bounty impact: "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."

## Likelihood Explanation

- Requires the Flexible HTTP feature to be enabled on the target subnet.
- Requires an attacker canister to submit 501+ flexible HTTP requests and allow them to expire — a one-time, bounded cycles cost.
- No privileged access, no key material, no majority corruption, no social engineering required.
- The condition is persistent: it cannot self-heal because the timed-out contexts block every subsequent block until they are delivered, which requires a valid block, which cannot be built under this condition.

## Recommendation

Fix `num_non_timeout_responses()` in `rs/types/types/src/batch/canister_http.rs` to exclude `FlexibleCanisterHttpError::Timeout` variants, mirroring how the `timeouts` field is already excluded:

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

## Proof of Concept

1. Enable Flexible HTTP on a test subnet.
2. Inject 501 `CanisterHttpRequestContext` entries with `Replication::Flexible`, all with `time = UNIX_EPOCH`.
3. Call `build_payload` with a `ValidationContext::time` past `UNIX_EPOCH + CANISTER_HTTP_TIMEOUT_INTERVAL`.
4. Parse the resulting bytes; assert `flexible_errors.len() == 501` and all entries are `FlexibleCanisterHttpError::Timeout`.
5. Call `validate_payload` on the same bytes.
6. Assert: validation returns `Err(TooManyResponses { received: 501 })`. Expected: `Ok(())`.

This is structurally identical to the existing passing test `timeouts_bypass_max_responses_per_block` but using `Replication::Flexible` contexts instead of `fully_replicated_contexts`.