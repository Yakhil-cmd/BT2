Audit Report

## Title
Non-Disclosed Rate-Limit Rule Metadata Exposed to Unprivileged Callers via Unguarded `#[query]` Methods — (`rs/boundary_node/rate_limits/canister/canister.rs`, `getter.rs`, `confidentiality_formatting.rs`)

## Summary

`get_rule_by_id`, `get_rules_by_incident_id`, and `get_config` are all `#[query]` methods. On the Internet Computer, `inspect_message` is invoked exclusively for ingress update messages and is never called for non-replicated query invocations. Because none of these three methods appear in `UPDATE_METHODS` or carry in-handler authorization checks, any anonymous caller can invoke them as non-replicated queries, bypassing `inspect_message` entirely. The `RuleConfidentialityFormatter` and `ConfigConfidentialityFormatter` only redact `rule_raw` and `description` for non-disclosed rules, leaving `rule_id`, `incident_id`, `added_in_version`, and `removed_in_version` always present in the response. An anonymous caller can therefore enumerate the full set of non-disclosed rules and incidents, their inter-relationships, and the exact canister versions at which each was deployed or removed.

## Finding Description

**Root cause — `inspect_message` does not fire for query calls.**

`inspect_message` is registered as the ingress filter hook: [1](#0-0) 

The IC protocol invokes this hook only for ingress update messages. Non-replicated query calls skip it unconditionally. The `else` branch that traps "all other calls" therefore never executes for query-type invocations.

**`get_rule_by_id` and `get_rules_by_incident_id` are `#[query]` methods absent from every guard.** [2](#0-1) 

Neither method is listed in `UPDATE_METHODS` nor equals `REPLICATED_QUERY_METHOD`. They carry no in-handler authorization check: [3](#0-2) 

**`RuleConfidentialityFormatter` leaves identifying metadata unredacted.**

For a non-disclosed rule (`disclosed_at.is_none()`), only `description` and `rule_raw` are cleared: [4](#0-3) 

The `From<OutputRuleMetadata> for api::OutputRuleMetadata` conversion always serializes `rule_id`, `incident_id`, `added_in_version`, and `removed_in_version`: [5](#0-4) 

**`RuleGetter.get()` confirms the leak path for `RestrictedRead` callers.** [6](#0-5) 

**`get_config` as a non-replicated query leaks `rule_id` and `incident_id` for all rules.**

`get_config` is also `#[query]` and bypasses `inspect_message` when called as a non-replicated query. `ConfigConfidentialityFormatter` similarly leaves `rule_id` and `incident_id` intact: [7](#0-6) 

The `From<OutputRule> for api::OutputRule` conversion always includes both IDs: [8](#0-7) 

**The existing unit test explicitly documents the leak.** [9](#0-8) 

The test asserts that an unauthorized (`RestrictedRead`) caller receives `rule_id`, `incident_id`, `added_in_version`, and `removed_in_version` for a non-disclosed rule.

## Impact Explanation

An anonymous caller obtains: the existence of every non-disclosed rate-limit rule and incident, the incident-to-rule mapping, and the exact canister versions at which each rule was added and removed. This reveals the structure and timing of active incident response before public disclosure. A sophisticated attacker monitoring the canister can detect when new rate-limit rules are being deployed and adjust evasion behavior accordingly, undermining the confidentiality guarantee that is the explicit design goal of the boundary node rate-limit canister. This constitutes a significant boundary node infrastructure security impact with concrete operational harm, fitting the **High** impact tier ($2,000–$10,000).

## Likelihood Explanation

Exploitation requires only standard IC query calls available to any anonymous principal — no special tooling, no privileged access, no brute-forcing. UUID enumeration is fully solved by calling `get_config` as a non-replicated query first. The attack is entirely local-testable, repeatable, and requires no network-level capability.

## Recommendation

1. **Add in-handler authorization checks** inside `get_rule_by_id`, `get_rules_by_incident_id`, and `get_config` that reject `RestrictedRead` (anonymous) callers at the application level, independent of `inspect_message`.
2. **Redact `rule_id` and `incident_id`** in both `RuleConfidentialityFormatter` and `ConfigConfidentialityFormatter` for non-disclosed rules, so that even if the methods remain callable, the existence of a non-disclosed rule is not confirmed.
3. **Do not rely solely on `inspect_message`** for confidentiality enforcement — it is a pre-consensus optimization hint, not a security boundary for query calls.
4. Optionally convert `get_rule_by_id` and `get_rules_by_incident_id` to `#[update]` methods and add them to `UPDATE_METHODS` if replicated execution with `inspect_message` enforcement is the intended access model.

## Proof of Concept

```bash
# Step 1: Harvest all rule/incident IDs (including non-disclosed) via get_config query
dfx canister call rate_limits_canister get_config '(null)' --query
# Response includes rule_id and incident_id for ALL rules, disclosed or not.

# Step 2: For each non-disclosed rule_id obtained above:
dfx canister call rate_limits_canister get_rule_by_id '("<non-disclosed-uuid>")' --query
# Response: rule_id, incident_id, added_in_version, removed_in_version are present.
# Only rule_raw and description are null.

# Step 3: For each incident_id:
dfx canister call rate_limits_canister get_rules_by_incident_id '("<incident-uuid>")' --query
# Response: full metadata for all rules in the incident, including non-disclosed ones.
```

The existing unit test at `getter.rs` lines 433–446 already serves as a deterministic proof: it asserts that a `RestrictedRead` caller receives `rule_id`, `incident_id`, `added_in_version`, and `removed_in_version` for a non-disclosed rule, with only `rule_raw` and `description` nulled out.

### Citations

**File:** rs/boundary_node/rate_limits/canister/canister.rs (L30-31)
```rust
const UPDATE_METHODS: [&str; 2] = ["add_config", "disclose_rules"];
const REPLICATED_QUERY_METHOD: &str = "get_config";
```

**File:** rs/boundary_node/rate_limits/canister/canister.rs (L34-68)
```rust
#[inspect_message]
fn inspect_message() {
    // In order for this hook to succeed, accept_message() must be invoked.
    let caller_id: Principal = ic_cdk::api::caller();
    let called_method = ic_cdk::api::call::method_name();

    let (has_full_access, has_full_read_access) = with_canister_state(|state| {
        let authorized_principal = state.get_authorized_principal();
        (
            Some(caller_id) == authorized_principal,
            state.is_api_boundary_node_principal(&caller_id),
        )
    });

    if called_method == REPLICATED_QUERY_METHOD {
        if has_full_access || has_full_read_access {
            ic_cdk::api::call::accept_message();
        } else {
            ic_cdk::api::trap(
                "message_inspection_failed: method call is prohibited in the current context",
            );
        }
    } else if UPDATE_METHODS.contains(&called_method.as_str()) {
        if has_full_access {
            ic_cdk::api::call::accept_message();
        } else {
            ic_cdk::api::trap("message_inspection_failed: unauthorized caller");
        }
    } else {
        // All others calls are rejected
        ic_cdk::api::trap(
            "message_inspection_failed: method call is prohibited in the current context",
        );
    }
}
```

**File:** rs/boundary_node/rate_limits/canister/canister.rs (L123-146)
```rust
#[query]
fn get_rule_by_id(rule_id: RuleId) -> GetRuleByIdResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter = RuleConfidentialityFormatter;
        let getter = RuleGetter::new(state, formatter, access_resolver);
        getter.get(&rule_id)
    })?;
    Ok(response)
}

/// Retrieves all rate-limit rules associated with a specific incident ID, applying confidentiality formatting, based on caller's access level and rule's confidentiality status
#[query]
fn get_rules_by_incident_id(incident_id: IncidentId) -> GetRulesByIncidentIdResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter = RuleConfidentialityFormatter;
        let getter = IncidentGetter::new(state, formatter, access_resolver);
        getter.get(&incident_id)
    })?;
    Ok(response)
}
```

**File:** rs/boundary_node/rate_limits/canister/confidentiality_formatting.rs (L14-29)
```rust
impl ConfidentialityFormatting for ConfigConfidentialityFormatter {
    type Input = OutputConfig;

    fn format(&self, config: OutputConfig) -> OutputConfig {
        let mut config = config;
        config.is_redacted = true;
        // Redact (hide) fields of non-disclosed rules
        config.rules.iter_mut().for_each(|rule| {
            if rule.disclosed_at.is_none() {
                rule.description = None;
                rule.rule_raw = None;
            }
        });
        config
    }
}
```

**File:** rs/boundary_node/rate_limits/canister/confidentiality_formatting.rs (L31-42)
```rust
impl ConfidentialityFormatting for RuleConfidentialityFormatter {
    type Input = OutputRuleMetadata;

    fn format(&self, rule: OutputRuleMetadata) -> OutputRuleMetadata {
        let mut rule = rule;
        // Redact (hide) fields of non-disclosed rule
        if rule.disclosed_at.is_none() {
            rule.description = None;
            rule.rule_raw = None;
        }
        rule
    }
```

**File:** rs/boundary_node/rate_limits/canister/types.rs (L78-87)
```rust
impl From<OutputRule> for api::OutputRule {
    fn from(value: OutputRule) -> Self {
        api::OutputRule {
            description: value.description,
            rule_id: value.id.to_string(),
            incident_id: value.incident_id.to_string(),
            rule_raw: value.rule_raw,
        }
    }
}
```

**File:** rs/boundary_node/rate_limits/canister/types.rs (L305-317)
```rust
impl From<OutputRuleMetadata> for api::OutputRuleMetadata {
    fn from(value: OutputRuleMetadata) -> Self {
        api::OutputRuleMetadata {
            rule_id: value.id.0.to_string(),
            incident_id: value.incident_id.0.to_string(),
            rule_raw: value.rule_raw,
            description: value.description,
            disclosed_at: value.disclosed_at,
            added_in_version: value.added_in_version,
            removed_in_version: value.removed_in_version,
        }
    }
}
```

**File:** rs/boundary_node/rate_limits/canister/getter.rs (L234-245)
```rust
        let is_authorized_viewer = self.access_resolver.get_access_level()
            == AccessLevel::FullAccess
            || self.access_resolver.get_access_level() == AccessLevel::FullRead;

        if is_authorized_viewer {
            return Ok(output_rule.into());
        }

        // Hide non-disclosed rules from unauthorized viewers.
        let output_rule = self.formatter.format(output_rule);

        Ok(output_rule.into())
```

**File:** rs/boundary_node/rate_limits/canister/getter.rs (L433-447)
```rust
        let response = getter_unauthorized.get(&rule_id.0.to_string()).unwrap();
        // rule fields are hidden
        assert_eq!(
            response,
            api::OutputRuleMetadata {
                rule_id: rule_id.0.to_string(),
                incident_id: incident_id.0.to_string(),
                rule_raw: None,
                description: None,
                disclosed_at: None,
                added_in_version: 1,
                removed_in_version: Some(3),
            }
        );
    }
```
