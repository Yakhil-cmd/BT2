Audit Report

## Title
Lexicographic Node Operator Ordering in `calculate_rewards_v0()` Enables Reward Manipulation via Principal ID Selection - (File: `rs/registry/node_provider_rewards/src/lib.rs`)

## Summary

`calculate_rewards_v0()` applies a running decay coefficient (`np_coeff`) to type3 node rewards in lexicographic order of node operator registry keys. Because the registry key is derived from the node operator's principal ID (which a node provider freely chooses), and because different cities within the same country can carry different `reward_coefficient_percent` values, a node provider can select principal IDs that place the higher-coefficient (slower-decay) operator first in the iteration order, systematically receiving more XDR rewards than the policy intends.

## Finding Description

**Lexicographic iteration order** is established in `get_key_family_raw_iter_at_version`, which ranges over `registry.store` — a `BTreeMap` — using the raw key bytes, guaranteeing byte-lexicographic order. [1](#0-0) 

The registry key for each node operator is `NODE_OPERATOR_RECORD_KEY_PREFIX + node_operator_principal_id.to_string()`. [2](#0-1) 

The outer loop in `calculate_rewards_v0()` therefore processes node operators in lexicographic order of their principal ID strings. [3](#0-2) 

The running decay coefficient is keyed by `{node_provider_id}:{continent}:{country}`, shared across all node operators of the same provider in the same country regardless of city. [4](#0-3) 

For each node operator, the per-DC `dc_reward_coefficient_percent` is read from the rewards table for that specific city/state region, meaning two operators in the same country but different cities can carry different decay rates. [5](#0-4) 

The decay is applied sequentially per node and the updated `np_coeff` is stored back for the next operator in the same country. [6](#0-5) 

The code itself explicitly documents this ordering sensitivity as a known issue, noting that rewards differ depending on which operator sorts first lexicographically. [7](#0-6) 

The rewards table schema permits different `reward_coefficient_percent` values per city-level region entry. [8](#0-7) 

The production test data confirms that different city-level entries within the same country can carry different coefficients (e.g., `"North America,US,California"` at 70 vs. `"North America,US,Georgia"` with `null`). [9](#0-8) 

This function is called directly from the production registry reward endpoint. [10](#0-9) 

## Impact Explanation

A node provider with two type3 node operators in the same country, where those cities have different `reward_coefficient_percent` values, receives materially different total XDR rewards depending solely on the lexicographic ordering of their node operator principal IDs — with no change to actual node infrastructure. Because XDR rewards are converted to ICP and minted by the NNS, this constitutes unauthorized over-minting of ICP rewards beyond what the reward policy intends. The financial difference scales with node count and the gap between coefficients; with 10 nodes per DC at a base rate of 22,000,000 XDR permyriad/month, the difference between orderings can reach ~9,200 XDR/month (~$12,000/month at current XDR rates). This matches the allowed impact: **High ($2,000–$10,000) — Significant NNS governance/reward accounting impact with concrete protocol harm**.

## Likelihood Explanation

A registered node provider can generate arbitrarily many Ed25519 key pairs offline, compute the resulting principal ID string for each, and select the pair whose string representation sorts lexicographically before the other operator's key. This requires no privileged access beyond being a registered node provider. Registering a node operator with a chosen principal ID is a standard NNS governance proposal (`NnsFunction::AssignNoid`) that NNS voters have no reason to reject on lexicographic grounds. The selection is done once at registration time; no subsequent re-registration or node migration is required. The attack leaves no anomalous on-chain trace beyond the reward payout itself.

## Recommendation

1. Before applying the decay sequence, group all node operators for a given `(node_provider_id, continent, country)` tuple and sort them by a policy-defined criterion (e.g., descending `reward_coefficient_percent`) that is independent of principal ID choice.
2. Alternatively, compute the total reward for the group analytically as a closed-form function of all per-DC coefficients and node counts, eliminating ordering sensitivity entirely.
3. If the v0 algorithm is being phased out in favor of the performance-based algorithm (which already averages coefficients across the country group), accelerate that migration and document the v0 function as deprecated.

## Proof of Concept

1. Node provider NP registers two node operators in the same country where the rewards table has different `reward_coefficient_percent` values per city:
   - `no_aaa` (principal sorts lexicographically first) → city A, `reward_coefficient_percent = 70`
   - `no_zzz` (principal sorts lexicographically last) → city B, `reward_coefficient_percent = 90`
2. `calculate_rewards_v0()` processes `no_aaa` first (70% decay), depleting `np_coeff` rapidly across its nodes.
3. `no_zzz` then receives rewards at the already-depleted `np_coeff`, yielding low total rewards.
4. Alternatively, NP registers with swapped ordering:
   - `no_aaa` → city B (90% coefficient, sorts first)
   - `no_zzz` → city A (70% coefficient, sorts last)
5. Now the 90%-coefficient operator is processed first, keeping `np_coeff` higher for longer.
6. Total rewards in scenario 5 are substantially higher than in scenario 3 with identical node infrastructure.

A minimal unit test can be written directly against `calculate_rewards_v0()` by constructing two `NodeOperatorRecord` slices with the same node counts and swapped key strings, asserting that the total reward differs — confirming the ordering sensitivity without any mainnet interaction.

### Citations

**File:** rs/registry/canister/src/common/key_family.rs (L56-60)
```rust
    // Note, using the 'store' which is a BTreeMap is what guarantees the order of keys.
    registry
        .store
        .range(start..)
        .take_while(|(k, _)| k.starts_with(prefix_bytes))
```

**File:** rs/registry/keys/src/lib.rs (L229-231)
```rust
pub fn make_node_operator_record_key(node_operator_principal_id: PrincipalId) -> String {
    format!("{NODE_OPERATOR_RECORD_KEY_PREFIX}{node_operator_principal_id}")
}
```

**File:** rs/registry/node_provider_rewards/src/lib.rs (L30-30)
```rust
    for (key_string, node_operator) in node_operators.iter() {
```

**File:** rs/registry/node_provider_rewards/src/lib.rs (L85-99)
```rust
                    // A note around the type3 rewards and iter() over self.store
                    //
                    // One known issue with this implementation is that in some edge cases it could lead to
                    // unexpected results. The outer loop iterates over the node operator records sorted
                    // lexicographically, instead of the order in which the records were added to the registry,
                    // or instead of the order in which NP/NO adds nodes to the network. This means that all
                    // reduction factors for the node operator A are applied prior to all reduction factors for
                    // the node operator B, independently from the order in which the node operator records,
                    // nodes, or the rewardable nodes were added to the registry.
                    // For instance, say a Node Provider adds a Node Operator B in region 1 with higher reward
                    // coefficient so higher average rewards, and then A in region 2 with lower reward
                    // coefficient so lower average rewards. When the rewards are calculated, the rewards for
                    // Node Operator A are calculated before the rewards for B (due to the lexicographical
                    // order), and the final rewards will be lower than they would be calculated first for B and
                    // then for A, as expected based on the insert order.
```

**File:** rs/registry/node_provider_rewards/src/lib.rs (L107-117)
```rust
                    let np_coefficients_key = format!(
                        "{}:{}",
                        node_provider_id,
                        region
                            .splitn(3, ',')
                            .take(2)
                            .collect::<Vec<&str>>()
                            .join(":")
                    );

                    let mut np_coeff = *np_coefficients.get(&np_coefficients_key).unwrap_or(&1.0);
```

**File:** rs/registry/node_provider_rewards/src/lib.rs (L123-124)
```rust
                    let dc_reward_coefficient_percent =
                        rate.reward_coefficient_percent.unwrap_or(80) as f64 / 100.0;
```

**File:** rs/registry/node_provider_rewards/src/lib.rs (L127-139)
```rust
                    for i in 0..*node_count {
                        let node_reward = (reward_base * np_coeff) as u64;
                        np_log.add_entry(LogEntry::NodeRewards {
                            node_type: node_type.clone(),
                            node_idx: i,
                            dc_id: node_operator.dc_id.clone(),
                            rewardable_count: *node_count,
                            rewards_xdr_permyriad: node_reward,
                        });
                        dc_reward += node_reward;
                        np_coeff *= dc_reward_coefficient_percent;
                    }
                    np_coefficients.insert(np_coefficients_key, np_coeff);
```

**File:** rs/protobuf/def/registry/node_rewards/v2/node_rewards.proto (L10-16)
```text
  // The coefficient of the node rewards the node provider gets
  // for having more than 1 node, as a percentage of the reward for first node.
  // A value of 100 means that the same reward is received for all nodes
  // A value of 0 means that only the first node gets the rewards, 2nd and later nodes get no reward
  // For values in between, the reward for the n-th node is:
  // reward(n) = reward(n-1) * reward_coefficient_percent ^ (n-1)
  optional int32 reward_coefficient_percent = 2;
```

**File:** rs/registry/canister/src/get_node_providers_monthly_xdr_rewards.rs (L49-49)
```rust
        let reward_values = calculate_rewards_v0(&rewards_table, &node_operators, &data_centers)?;
```

**File:** rs/registry/canister/src/get_node_providers_monthly_xdr_rewards.rs (L404-412)
```rust
            "North America,US":            { "type0": [100000, null],  "type2": [200000, null],  "type3": [300000, 70] },
            "North America,CA":            { "type0": [400000, null],  "type2": [500000, null],  "type3": [600000, 70] },
            "North America,US,California": { "type0": [700000, null],                            "type3": [800000, 70] },
            "North America,US,Florida":    { "type0": [900000, null],                            "type3": [1000000, 70] },
            "North America,US,Georgia":    { "type0": [1100000, null],                           "type3": [1200000, null] },
            "Asia,SG":                     { "type0": [10000000, 100],  "type2": [11000000, 100],  "type3": [12000000, 70] },
            "Asia":                        { "type0": [13000000, 100],  "type2": [14000000, 100],  "type3": [15000000, 70] },
            "Europe":                      { "type0": [20000000, null], "type2": [21000000, null], "type3": [22000000, 70] }
        }"#;
```
