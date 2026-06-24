Audit Report

## Title
`inspect_message` Guard Bypassed via Query Calls, Leaking Confidential Rate-Limit Rule Metadata - (File: `rs/boundary_node/rate_limits/canister/canister.rs`)

## Summary
The rate-limits canister uses an `inspect_message` hook to restrict ingress access to `get_config`, `add_config`, and `disclose_rules`. However, `get_config`, `get_rule_by_id`, and `get_rules_by_incident_id` are all annotated `#[query]`, and the IC protocol never invokes `inspect_message` for query calls. Any unprivileged caller — including anonymous principals — can invoke these methods as query calls, bypassing the guard entirely. The `RestrictedRead` fallback path redacts `rule_raw` and `description` but still returns `rule_id`, `incident_id`, `added_in_version`, and `removed_in_version` for every non-disclosed rule, leaking metadata the canister explicitly treats as confidential.

## Finding Description
`inspect_message` is an IC-CDK hook invoked only for ingress **update** messages before consensus. It is never called for query calls — this is a fundamental IC protocol property.

The hook at `canister.rs` L34–68 guards three paths:
- `get_config` (as `REPLICATED_QUERY_METHOD`): allowed only for `authorized_principal` or API boundary nodes.
- `add_config`, `disclose_rules`: allowed only for `authorized_principal`.
- Everything else (including `get_rule_by_id`, `get_rules_by_incident_id`): unconditionally rejected.

All three read methods are annotated `#[query]` (`canister.rs` L110, L123, L136), so the IC runtime routes them directly to execution without ever invoking `inspect_message`. The constant `REPLICATED_QUERY_METHOD = "get_config"` signals developer intent that `get_config` should behave as a replicated query (update call), but the `#[query]` annotation makes it reachable as a plain query call, silently bypassing the guard.

Inside each method, `AccessLevelResolver::get_access_level()` (`access_control.rs` L38–55) returns `AccessLevel::RestrictedRead` for any caller that is neither the `authorized_principal` nor a registered API boundary node. The confidentiality formatters (`confidentiality_formatting.rs` L17–28, L34–42) then null out `rule_raw` and `description` for non-disclosed rules (those with `disclosed_at == None`), but leave `rule_id`, `incident_id`, `added_in_version`, and `removed_in_version` intact. This is confirmed by the unit test at `getter.rs` L433–446, which explicitly asserts that an unauthorized caller receives `rule_id`, `incident_id`, `added_in_version: 1`, and `removed_in_version: Some(3)` for a non-disclosed rule.

The exploit path:
1. Any principal (including anonymous) issues a query call to `get_config(null)`.
2. `inspect_message` is never invoked; execution proceeds directly.
3. `AccessLevelResolver` returns `RestrictedRead`.
4. `ConfigConfidentialityFormatter` redacts `rule_raw`/`description` but returns all rule UUIDs and incident UUIDs verbatim.
5. The caller now knows every non-disclosed rule's UUID, its associated incident UUID, and the config versions in which it was added/removed.
6. The caller can then call `get_rule_by_id(<uuid>)` or `get_rules_by_incident_id(<incident_uuid>)` as query calls (also bypassing `inspect_message`, which would have rejected these methods entirely for update calls) to retrieve per-rule version metadata.

## Impact Explanation
The rate-limits canister is designed to keep non-disclosed rules confidential because they describe active security incidents at the boundary node layer. Leaking rule UUIDs, incident UUIDs, and version timelines allows an attacker to confirm that a specific incident is being tracked before public disclosure, correlate incident UUIDs across calls to reconstruct the timeline of security events, and determine which config versions introduced or removed specific rules. This constitutes a significant boundary/API security impact with concrete harm to the confidentiality model of the boundary node infrastructure. This matches the High impact class: "Significant boundary/API security impact with concrete user or protocol harm."

## Likelihood Explanation
The attack requires no special privilege, no key material, and no inter-canister coordination. Any user with an IC identity (including anonymous principal) can issue a query call to the canister's public endpoint. The canister is deployed on the NNS subnet with a publicly known canister ID. Exploitation is trivially scriptable with `dfx` or any IC agent library. The attack is repeatable at will with zero cost.

## Recommendation
1. **Change `get_config`, `get_rule_by_id`, and `get_rules_by_incident_id` from `#[query]` to `#[update]`** so that `inspect_message` is actually invoked for every ingress call. This matches the developer intent expressed by `REPLICATED_QUERY_METHOD`.
2. **Add an explicit caller check inside each method** as defense-in-depth (independent of `inspect_message`), so that inter-canister callers are also subject to the same access control.
3. Alternatively, if `#[query]` semantics are required for latency, remove the `inspect_message` entries for these methods and enforce access control solely through `AccessLevelResolver`, but ensure `RestrictedRead` returns no metadata whatsoever (not even `rule_id` or `incident_id`) for non-disclosed rules.

## Proof of Concept
```bash
# Any principal, including anonymous, can issue:
dfx canister --network ic call <rate-limits-canister-id> get_config '(null)' --query
# Response includes rule_id and incident_id for every non-disclosed rule.

dfx canister --network ic call <rate-limits-canister-id> get_rule_by_id '("<uuid>")' --query
# Returns incident_id, added_in_version, removed_in_version for a non-disclosed rule.

dfx canister --network ic call <rate-limits-canister-id> get_rules_by_incident_id '("<incident_uuid>")' --query
# Returns metadata for all rules under a non-disclosed incident.
```

A deterministic integration test can be written using PocketIC (`integration_tests/src/pocket_ic_helpers.rs`): install the canister, add a config with a non-disclosed rule, then call `get_config` as a query from an anonymous principal and assert that `rule_id` and `incident_id` are present in the response while `rule_raw` and `description` are `None`.