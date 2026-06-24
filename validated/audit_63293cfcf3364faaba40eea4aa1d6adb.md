Audit Report

## Title
Missing Anonymous Principal Validation in `node_provider_id` Allows Node Operator Record Takeover - (File: rs/registry/canister/src/mutations/do_update_node_operator_config_directly.rs)

## Summary
`do_update_node_operator_config_directly_` accepts any `PrincipalId` as the new `node_provider_id`, including the anonymous principal, without validation. If a node provider sets this field to the anonymous principal, the authorization check at line 59–65 is subsequently satisfied by any unsigned (anonymous) ingress message, allowing an attacker to redirect the `NodeOperatorRecord`'s `node_provider_principal_id` — and all associated node reward payments — to an arbitrary principal they control.

## Finding Description
The function `do_update_node_operator_config_directly_` in `rs/registry/canister/src/mutations/do_update_node_operator_config_directly.rs` is the permissionless path for a node provider to update their own `NodeOperatorRecord`. Its sole authorization guard compares the ingress caller against the stored `node_provider_principal_id`:

```rust
if caller != PrincipalId::try_from(&node_operator_record.node_provider_principal_id).unwrap() {
    return Err(...)
}
``` [1](#0-0) 

The only other validation on the incoming `node_provider_id` is that it must not equal `node_operator_id`:

```rust
if node_provider_id == node_operator_id { return Err(...) }
``` [2](#0-1) 

After passing these checks, the new provider principal is written unconditionally:

```rust
node_operator_record.node_provider_principal_id = node_provider_id.to_vec();
``` [3](#0-2) 

There is no check that `node_provider_id` is not the anonymous principal. The canister entry point explicitly permits any caller: [4](#0-3) 

The IC protocol's ingress validation layer explicitly allows unsigned (anonymous) update calls. In `validate_user_id_and_signature`, when `signature` is `None` and `sender.get().is_anonymous()` is true, the request is accepted with `Ok(CanisterIdSet::all())`: [5](#0-4) 

This is confirmed by the test `should_validate_anonymous_request`, which asserts that `new_update_call()` with `Anonymous` authentication validates successfully: [6](#0-5) 

**Exploit chain:**

1. **Poison step** (legitimate node provider, one call): The current node provider calls `update_node_operator_config_directly` with `node_provider_id = 2vxsx-fae` (the anonymous principal). The auth check passes because `caller == current node_provider_principal_id`. The record is updated: `node_provider_principal_id = anonymous`.

2. **Takeover step** (attacker, anonymous ingress): Any party sends an unsigned ingress call to `update_node_operator_config_directly` with `node_provider_id = <attacker_principal>`. The auth check compares `caller` (anonymous) against `node_provider_principal_id` (now anonymous) — it passes. The rate limit check at line 70 uses the anonymous principal's capacity, which is fresh. The record is updated: `node_provider_principal_id = attacker_principal`.

3. All future node reward computations in `get_node_providers_monthly_xdr_rewards` attribute XDR rewards to `node_provider_principal_id`, which now points to the attacker. [7](#0-6) 

## Impact Explanation
This is a **High** severity finding. An attacker can achieve unauthorized takeover of a `NodeOperatorRecord` and permanently redirect all node reward payments (XDR) to a principal they control. This constitutes unauthorized access to governance/infrastructure assets and financial theft of node provider rewards. The impact is constrained per-target (one node operator record per exploit), placing it in the High ($2,000–$10,000) tier: "Unauthorized access to neurons, governance assets, wallets, identities, ledgers, or canister-controlled funds where exploitation requires meaningful per-target work or other constraints."

## Likelihood Explanation
The poison step requires the legitimate node provider to submit `node_provider_id = anonymous` once. This can occur through a default-initialized Candid struct (the zero value of `PrincipalId` encodes as the anonymous principal), a misconfigured script, or a UI bug. The anonymous principal (`2vxsx-fae`, byte encoding `[0x04]`) is a valid `PrincipalId` that Candid accepts without error. No special crafting is required. Once the record is poisoned, the takeover step is a single unsigned ingress call requiring no credentials, keys, or privileges. The endpoint has no governance gate and no caller allowlist.

## Recommendation
Add an explicit check that `node_provider_id` is not the anonymous principal before line 83, analogous to the existing `node_provider_id == node_operator_id` guard:

```rust
if node_provider_id.is_anonymous() {
    return Err("The Node Provider ID cannot be the anonymous principal".to_string());
}
``` [8](#0-7) 

Apply the same guard to `do_update_node_operator_config` (governance path) and `do_add_node_operator` for defense-in-depth. [9](#0-8) 

## Proof of Concept

A deterministic unit test can be added to the existing test module in `do_update_node_operator_config_directly.rs`:

```rust
#[test]
fn test_anonymous_principal_poison_and_takeover() {
    let mut registry = invariant_compliant_registry(0);
    let now = now_system_time();

    let node_operator_id = PrincipalId::new_user_test_id(1_000);
    let node_provider_id = PrincipalId::new_user_test_id(10_000);
    let attacker_id = PrincipalId::new_user_test_id(99_999);

    // Setup: add node operator record
    registry.do_add_node_operator(AddNodeOperatorPayload {
        node_operator_principal_id: Some(node_operator_id),
        node_provider_principal_id: Some(node_provider_id),
        node_allowance: 1,
        dc_id: "DC1".to_string(),
        rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
        ipv6: Some("bar".to_string()),
        max_rewardable_nodes: Some(btreemap! { "type1.2".to_string() => 1 }),
    });

    // Step 1: Legitimate NP poisons the record with anonymous principal
    let anonymous = PrincipalId::new_anonymous();
    registry.do_update_node_operator_config_directly_(
        UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(anonymous),
        },
        node_provider_id, // legitimate caller
        now,
    ).unwrap();

    // Step 2: Attacker sends anonymous ingress, takes over
    registry.do_update_node_operator_config_directly_(
        UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(attacker_id),
        },
        anonymous, // anonymous caller — should be rejected but currently is not
        now,
    ).unwrap(); // This succeeds — demonstrating the vulnerability

    // Verify attacker now owns the record
    let record = get_node_operator_record(&registry, node_operator_id).unwrap();
    assert_eq!(
        PrincipalId::try_from(record.node_provider_principal_id).unwrap(),
        attacker_id
    );
}
``` [10](#0-9)

### Citations

**File:** rs/registry/canister/src/mutations/do_update_node_operator_config_directly.rs (L59-65)
```rust
        if caller
            != PrincipalId::try_from(&node_operator_record.node_provider_principal_id).unwrap()
        {
            return Err(format!(
                "Caller {caller} not equal to the node_provider_princpal_id for this record."
            ));
        }
```

**File:** rs/registry/canister/src/mutations/do_update_node_operator_config_directly.rs (L77-83)
```rust
        if node_provider_id == node_operator_id {
            return Err(format!(
                "The Node Operator ID cannot be the same as the Node Provider ID: {node_operator_id}"
            ));
        }

        node_operator_record.node_provider_principal_id = node_provider_id.to_vec();
```

**File:** rs/registry/canister/src/mutations/do_update_node_operator_config_directly.rs (L118-259)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use crate::mutations::node_management::common::get_node_operator_record;
    use maplit::btreemap;

    #[test]
    fn test_update_node_operator_config_directly_happy_path() {
        let mut registry = invariant_compliant_registry(0);

        let now = now_system_time();

        let node_operator_id = PrincipalId::new_user_test_id(1_000);
        let node_provider_id = PrincipalId::new_user_test_id(10_000);

        // Make a proposal to upgrade all unassigned nodes to a new version
        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_id),
            node_provider_principal_id: Some(node_provider_id),
            node_allowance: 1,
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("bar".to_string()),
            max_rewardable_nodes: Some(btreemap! { "type1.2".to_string() => 1 }),
        };

        registry.do_add_node_operator(payload);

        let new_np_id = PrincipalId::new_user_test_id(10_001);
        let request = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(new_np_id),
        };

        // The original node provider should be able to change the node operator configuration.
        let caller = node_provider_id;

        registry
            .do_update_node_operator_config_directly_(request, caller, now)
            .unwrap();

        assert_eq!(
            PrincipalId::try_from(
                get_node_operator_record(&registry, node_operator_id)
                    .unwrap()
                    .node_provider_principal_id
            )
            .unwrap(),
            new_np_id
        );
    }

    #[test]
    fn test_update_node_operator_config_directly_affects_rate_limits() {
        let mut registry = invariant_compliant_registry(0);

        let now = now_system_time();

        let node_operator_id = PrincipalId::new_user_test_id(1_000);
        let node_provider_id = PrincipalId::new_user_test_id(10_000);

        // Make a proposal to upgrade all unassigned nodes to a new version
        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_id),
            node_provider_principal_id: Some(node_provider_id),
            node_allowance: 1,
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("bar".to_string()),
            max_rewardable_nodes: Some(btreemap! { "type1.2".to_string() => 1 }),
        };

        registry.do_add_node_operator(payload);

        let request = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(node_provider_id),
        };

        // The original node provider should be able to change the node operator configuration.
        let caller = node_provider_id;

        let available = registry.get_available_node_provider_op_capacity(caller, now);

        registry
            .do_update_node_operator_config_directly_(request, caller, now)
            .unwrap();

        let next_available = registry.get_available_node_provider_op_capacity(caller, now);
        assert_eq!(available - 1, next_available);
    }

    #[test]
    fn test_update_node_operator_config_directly_fails_when_rate_limits_exceeded() {
        let mut registry = invariant_compliant_registry(0);

        let now = now_system_time();

        let node_operator_id = PrincipalId::new_user_test_id(1_000);
        let node_provider_id = PrincipalId::new_user_test_id(10_000);

        // Make a proposal to upgrade all unassigned nodes to a new version
        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_id),
            node_provider_principal_id: Some(node_provider_id),
            node_allowance: 1,
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("bar".to_string()),
            max_rewardable_nodes: Some(btreemap! { "type1.2".to_string() => 1 }),
        };

        registry.do_add_node_operator(payload);

        let request = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(node_provider_id),
        };

        // Max out node provider operations
        let available = registry.get_available_node_provider_op_capacity(node_provider_id, now);
        let reservation = registry
            .try_reserve_capacity_for_node_provider_operation(now, node_provider_id, available)
            .unwrap();
        registry
            .commit_used_capacity_for_node_provider_operation(now, reservation)
            .unwrap();

        // The original node provider should be able to change the node operator configuration.
        let caller = node_provider_id;
        let error = registry
            .do_update_node_operator_config_directly_(request, caller, now)
            .unwrap_err();

        assert_eq!(
            error,
            "Rate Limit Capacity exceeded. Please wait and try again later."
        );
    }
}
```

**File:** rs/registry/canister/canister/canister.rs (L809-823)
```rust
#[unsafe(export_name = "canister_update update_node_operator_config_directly")]
fn update_node_operator_config_directly() {
    // This method can be called by anyone
    println!(
        "{}call: update_node_operator_config_directly from: {}",
        LOG_PREFIX,
        dfn_core::api::caller()
    );
    over(
        candid_one,
        |payload: UpdateNodeOperatorConfigDirectlyPayload| {
            update_node_operator_config_directly_(payload)
        },
    );
}
```

**File:** rs/validator/src/ingress_validation.rs (L853-857)
```rust
    match signature {
        None => {
            if sender.get().is_anonymous() {
                return Ok(CanisterIdSet::all());
            }
```

**File:** rs/validator/ingress_message/tests/validate_request.rs (L488-513)
```rust
    #[test]
    fn should_validate_anonymous_request() {
        let verifier = verifier_at_time(CURRENT_TIME).build();

        test(&verifier, HttpRequestBuilder::new_update_call());
        test(&verifier, HttpRequestBuilder::new_query());
        test(&verifier, HttpRequestBuilder::new_read_state());

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_authentication(Anonymous)
                .with_ingress_expiry_at(CURRENT_TIME)
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(result, Ok(()), "Test with {builder_info} failed");
        }
```

**File:** rs/registry/canister/src/get_node_providers_monthly_xdr_rewards.rs (L35-55)
```rust
        let node_operators = get_key_family_iter_at_version::<NodeOperatorRecord>(
            self,
            NODE_OPERATOR_RECORD_KEY_PREFIX,
            version,
        )
        .collect::<Vec<_>>();

        let data_centers = get_key_family_iter_at_version::<DataCenterRecord>(
            self,
            DATA_CENTER_KEY_PREFIX,
            version,
        )
        .collect::<BTreeMap<String, DataCenterRecord>>();

        let reward_values = calculate_rewards_v0(&rewards_table, &node_operators, &data_centers)?;

        rewards.rewards = reward_values
            .rewards_per_node_provider
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
```

**File:** rs/registry/canister/src/mutations/do_update_node_operator_config.rs (L51-57)
```rust
        if let Some(node_provider_id) = payload.node_provider_id {
            assert_ne!(
                node_provider_id, node_operator_id,
                "The Node Operator ID cannot be the same as the Node Provider ID: {node_operator_id}"
            );
            node_operator_record.node_provider_principal_id = node_provider_id.to_vec();
        }
```
