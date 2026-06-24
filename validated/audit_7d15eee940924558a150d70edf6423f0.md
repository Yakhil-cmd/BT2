Audit Report

## Title
Anonymous `read_state` Requests for Large Subtree Paths Enable Computational Amplification DoS Against Replica - (File: `rs/http_endpoints/public/src/read_state.rs`)

## Summary
The IC replica's `read_state` endpoint unconditionally accepts anonymous requests for entire large subtrees (`["subnet"]`, `["api_boundary_nodes"]`) with no expiry enforcement and no per-path cost differentiation. Each such request triggers full `materialize_partial` + `hash_tree.witness` Merkle proof generation proportional to the subtree size. An attacker can sustain a stream of these cheap-to-construct requests to saturate the `read_state` blocking thread pool, causing legitimate ingress-status polling requests to receive `429 Too Many Requests`.

## Finding Description
**Expiry bypass for anonymous senders.** In `rs/validator/src/ingress_validation.rs` lines 165–168, `validate_ingress_expiry` is skipped when `request.sender().get().is_anonymous()`. This is confirmed by the explicit test `should_not_error_when_anonymous_read_state_request_expired` at `rs/validator/ingress_message/tests/validate_request.rs` lines 281–292, which asserts that an already-expired anonymous `read_state` request returns `Ok(())`. An attacker can therefore reuse a single crafted request body indefinitely without rotating `ingress_expiry`.

**Unconditional allowance of subtree paths.** In `verify_paths` (`rs/http_endpoints/public/src/read_state.rs` lines 461–473), the match arms for `[b"api_boundary_nodes"]` and `[b"subnet"]` only record a metric and return `Ok(())`. No additional authorization, depth restriction on the *returned* subtree, or differentiated handling is applied.

**Expensive proof generation per request.** `get_certificate_and_create_response` (lines 355–403) calls `sparse_labeled_tree_from_paths` and then `certified_state_reader.read_certified_state_with_exclusion`. The implementation in `rs/state_manager/src/lib.rs` lines 3883–3887 performs `replicated_state_as_lazy_tree` → `materialize_partial` → `hash_tree.witness::<MixedHashTree>`, all proportional to the size of the requested subtree. The `["subnet"]` path covers all subnets' public keys, node public keys, canister ranges, and metrics — the largest subtree in the state tree.

**Concurrency limit is insufficient.** The `GlobalConcurrencyLimitLayer` applied at `rs/http_endpoints/public/src/lib.rs` lines 619–645 caps simultaneous in-flight requests but does not distinguish between cheap leaf-path requests and expensive subtree requests. Because each `["subnet"]` request holds a slot for significantly longer than a `["time"]` request, the effective throughput for legitimate requests is reduced by the amplification ratio. Sustained queue saturation causes `429` responses to legitimate callers polling ingress status.

## Impact Explanation
This is an application/platform-level DoS against the `read_state` endpoint of any publicly reachable replica node, not based on raw volumetric DDoS but on computational amplification. The `read_state` endpoint is mandatory for the IC user-facing protocol (ingress status polling). Saturating it on a replica degrades user-facing functionality for all users routed to that node. This matches the allowed impact: **High ($2,000–$10,000) — Application/platform-level DoS not based on raw volumetric DDoS**.

## Likelihood Explanation
The attack requires no credentials, no on-chain resources, no privileged access, and no victim interaction. The anonymous principal (`bytes([4])`) is the IC's built-in unauthenticated identity. The path `["subnet"]` is a single-label path trivially constructable in any CBOR library. The `ingress_expiry` field is ignored for anonymous senders, so a single request body can be replayed indefinitely. Replicas are directly reachable over HTTPS without passing through boundary-node rate limiting. The attack is low-cost for the attacker and high-cost per request for the replica.

## Recommendation
1. **Require authentication for subtree-root paths**: Restrict `["subnet"]` and `["api_boundary_nodes"]` (single-label paths that expand to entire subtrees) to non-anonymous senders in `verify_paths`, since these paths are used by infrastructure tooling rather than end users.
2. **Apply a separate, stricter concurrency limit for subtree paths**: Detect in `verify_paths` or `get_certificate_and_create_response` whether the requested labeled tree covers a large subtree, and route such requests through a tighter concurrency gate independent of leaf-path requests.
3. **Enforce expiry for all `read_state` requests**: Remove the anonymous expiry bypass in `rs/validator/src/ingress_validation.rs` lines 166–168, or at minimum enforce a short maximum TTL for anonymous requests, to prevent indefinite request replay.

## Proof of Concept
A minimal local integration test using PocketIC or a local replica:

```python
import cbor2, requests, threading

# Single reusable request body — ingress_expiry=0 is ignored for anonymous sender
envelope = {
    "content": {
        "request_type": "read_state",
        "sender": bytes([4]),       # anonymous principal
        "paths": [[b"subnet"]],     # entire subnet subtree
        "ingress_expiry": 0,        # bypassed for anonymous sender
    }
    # no sender_pubkey, no sender_sig
}
body = cbor2.dumps(envelope)
headers = {"Content-Type": "application/cbor"}
url = "https://<replica>/api/v2/subnet/<subnet-id>/read_state"

# Saturate the read_state concurrency limit
def flood():
    while True:
        requests.post(url, data=body, headers=headers)

threads = [threading.Thread(target=flood) for _ in range(200)]
for t in threads: t.start()

# Observe: legitimate read_state requests (e.g., request_status polling)
# begin returning HTTP 429 once the concurrency queue is full.
```

Each request: passes `validate_paths_width_and_depth` (1 path, 1 label), bypasses `validate_ingress_expiry` (anonymous sender), passes `verify_paths` (`["subnet"]` unconditionally allowed), then triggers full subnet-subtree `materialize_partial` + `hash_tree.witness` in `CertifiedStateSnapshotImpl::read_certified_state_with_exclusion`.