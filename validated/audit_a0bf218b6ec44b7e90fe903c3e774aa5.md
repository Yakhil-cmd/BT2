Audit Report

## Title
Cross-Operator `num_removed_same_ip_same_type` Quota Bypass in `do_add_node_` — (`rs/registry/canister/src/mutations/node_management/do_add_node.rs`)

## Summary
`do_add_node_` computes `num_removed_same_ip_same_type` by scanning all nodes at the target IP regardless of operator ownership, but computes `num_in_registry_same_type` by filtering only the caller's (OP2's) nodes. When a co-provider operator (OP1) has a node at the same IP with the same reward type, the subtrahend is inflated by OP1's node, causing the quota check `max_rewardable_nodes <= num_in_registry_same_type.saturating_sub(num_removed_same_ip_same_type)` to evaluate as `Q <= Q-1` (false), bypassing the quota. Because `make_remove_or_replace_node_mutations` permits cross-operator removal when DC and node provider match, OP1's node is removed and OP2's new node is inserted, leaving OP2 with Q+1 nodes of the given type against a governance-approved quota of Q.

## Finding Description
**Root cause — mismatched scoping between numerator and subtrahend.**

`scan_for_nodes_by_ip` (common.rs L240–249) returns every `NodeId` whose `http.ip_addr` matches, with no filter on `node_operator_id`. The loop at do_add_node.rs L96–103 increments `num_removed_same_ip_same_type` for each such node whose reward type matches the requested type — including nodes owned by a different operator (OP1).

```rust
// L96-103: no operator ownership check
for node_with_same_ip in &nodes_with_same_ip {
    let node_same_ip_reward_type = get_node_reward_type_for_node(self, *node_with_same_ip)...;
    if Some(node_same_ip_reward_type) == node_reward_type {
        num_removed_same_ip_same_type += 1;
    }
}
```

The quota numerator at L144–148 is correctly scoped to `caller_id`:

```rust
let num_in_registry_same_type = get_node_operator_nodes(self, caller_id)
    .into_iter()
    .filter_map(|node| node.node_reward_type)
    .filter(|t| t == &(node_reward_type as i32))
    .count() as u32;
```

The quota check at L151–152 then subtracts the globally-scoped counter from the per-operator count:

```rust
if max_rewardable_nodes_same_type
    <= num_in_registry_same_type.saturating_sub(num_removed_same_ip_same_type)
```

With OP2 at quota Q and OP1 owning one node of the same type at the target IP:
- `num_in_registry_same_type = Q` (OP2's nodes only)
- `num_removed_same_ip_same_type = 1` (OP1's node)
- Check: `Q <= Q.saturating_sub(1)` → `Q <= Q-1` → **false** → quota check passes

**Cross-operator removal path.**

`make_remove_or_replace_node_mutations` (do_remove_node_directly.rs L89–119) allows OP2 to remove OP1's node when `caller_id != node_operator_id` by asserting that both operators share the same `dc_id` and `node_provider_principal_id`. This is a documented intentional fallback for operator redeployment, but it is exploitable here because the quota check has already been bypassed before the removal mutations are applied.

## Impact Explanation
This is a significant NNS/registry security impact. The `max_rewardable_nodes` quota is set by NNS governance proposals and represents the governance-approved upper bound on rewardable nodes per operator per type. Bypassing it allows a node provider to register nodes beyond their governance-approved quota, enabling unauthorized node reward accrual and distortion of network topology beyond what governance approved. The bypass is repeatable: each cycle sacrifices one of OP1's nodes and gains one extra node for OP2, allowing gradual accumulation. This matches the **High** impact tier: "Significant NNS, SNS, or infrastructure security impact with concrete user or protocol harm."

## Likelihood Explanation
The preconditions are standard IC multi-operator deployment: a single node provider operating two operator principals in the same data center is the normal pattern for large node providers. No admin keys, no governance majority, no threshold corruption, and no leaked credentials are required — only two legitimately registered operator principals under the same node provider. The attack is fully self-contained and repeatable.

## Recommendation
Scope `num_removed_same_ip_same_type` to only count nodes belonging to `caller_id`, making the subtrahend consistent with the per-operator numerator:

```rust
for node_with_same_ip in &nodes_with_same_ip {
    let node_operator = get_node_operator_id_for_node(self, *node_with_same_ip)
        .map_err(|e| format!("{LOG_PREFIX}do_add_node: {e}"))?;
    if node_operator != caller_id {
        continue;
    }
    let node_same_ip_reward_type =
        get_node_reward_type_for_node(self, *node_with_same_ip)
            .map_err(|e| format!("{LOG_PREFIX}do_add_node: {e}"))?;
    if Some(node_same_ip_reward_type) == node_reward_type {
        num_removed_same_ip_same_type += 1;
    }
}
```

## Proof of Concept
Deterministic unit test (extend the existing test suite in `do_add_node.rs`):

```
Setup:
  NP  = PrincipalId::new_user_test_id(3000)
  OP1 = PrincipalId::new_user_test_id(2000), dc_id="dc1", node_provider=NP,
        max_rewardable_nodes={"type1": 1}
  OP2 = PrincipalId::new_user_test_id(2001), dc_id="dc1", node_provider=NP,
        max_rewardable_nodes={"type1": 1}

Step 1: OP1 calls do_add_node_(payload{http="192.0.2.1:4321", type=type1}, OP1)
        → N1 registered; OP1 at quota (1 node of type1)

Step 2: OP2 calls do_add_node_(payload{http="192.0.2.2:4321", type=type1}, OP2)
        → N2 registered; OP2 at quota (1 node of type1)

Step 3: OP2 calls do_add_node_(payload{http="192.0.2.1:4321", type=type1}, OP2)
        Expected (correct): Err("Node Operator has reached max_rewardable_nodes quota")
        Actual (buggy):     Ok(N3) — N1 removed, N3 inserted at 192.0.2.1

Assert: registry contains both N2 (OP2) and N3 (OP2), both type1
        → OP2 holds 2 nodes of type1 against a quota of 1
```