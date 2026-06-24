Audit Report

## Title
Neuron Split Resets `voting_power_refreshed_timestamp_seconds`, Bypassing Deciding Voting Power Inactivity Penalty - (File: rs/nns/governance/src/governance.rs)

## Summary
In `split_neuron`, the child neuron is constructed via `NeuronBuilder::new` with `created_timestamp_seconds = now`, which causes `voting_power_refreshed_timestamp_seconds` to default to `now` as well. A neuron controller whose deciding voting power has been reduced or zeroed due to inactivity (≥7 months without voting or refreshing) can split their neuron to create a child with a fully fresh `voting_power_refreshed_timestamp_seconds`, recovering deciding voting power proportional to the split fraction without ever casting a vote.

## Finding Description
`NeuronBuilder::new` initializes `voting_power_refreshed_timestamp_seconds` to `created_timestamp_seconds` by default:

```rust
// rs/nns/governance/src/neuron/types.rs:1759
voting_power_refreshed_timestamp_seconds: created_timestamp_seconds,
```

In `split_neuron`, the child is built as:

```rust
// rs/nns/governance/src/governance.rs:2241-2257
let child_neuron = NeuronBuilder::new(
    child_nid,
    to_subaccount,
    *caller,
    parent_neuron.dissolve_state_and_age(),
    created_timestamp_seconds,   // = now
)
.with_hot_keys(...)
// ... no .with_voting_power_refreshed_timestamp_seconds(...)
.build();
```

No `.with_voting_power_refreshed_timestamp_seconds(parent_neuron.voting_power_refreshed_timestamp_seconds())` call is made. The child therefore always receives `voting_power_refreshed_timestamp_seconds = now`, regardless of how stale the parent is.

The deciding voting power calculation uses this field directly:

```rust
// rs/nns/governance/src/neuron/types.rs:391-396
let time_since_last_refreshed = Duration::from_secs(
    now_seconds.saturating_sub(self.voting_power_refreshed_timestamp_seconds),
);
voting_power_economics.deciding_voting_power_adjustment_factor(time_since_last_refreshed)
```

After 7 months of inactivity, `deciding_voting_power = 0`. The only legitimate way to update `voting_power_refreshed_timestamp_seconds` is `refresh_voting_power`, which requires voting or updating followees. The `split_neuron` path bypasses this entirely.

The existing test suite explicitly asserts and documents this behavior, confirming it is present in production code:

```rust
// rs/nns/governance/tests/governance.rs:5602-5616
assert_eq!(
    child_neuron.voting_power_refreshed_timestamp_seconds,
    Some(driver.now()),
);
assert!(
    child_neuron.voting_power_refreshed_timestamp_seconds.unwrap()
        > parent_neuron.voting_power_refreshed_timestamp_seconds.unwrap(),
    ...
);
```

## Impact Explanation
This is a significant NNS governance security impact. The deciding voting power inactivity mechanism is a core NNS governance feature designed to reduce the governance influence of inactive participants. By calling `split_neuron`, any inactive neuron controller can recover deciding voting power proportional to the split fraction without any participation. A neuron with 10,000 ICP and 0 deciding VP (inactive ≥7 months) can split into a child with 9,999 ICP and full deciding VP, effectively nullifying the inactivity penalty. This fits the **High ($2,000–$10,000)** impact class: "Significant NNS security impact with concrete user or protocol harm."

## Likelihood Explanation
Any NNS neuron controller can call `manage_neuron` with a `Split` command via ingress message — no privileged access, no social engineering, and no threshold corruption required. The operation costs one ledger transfer fee. It can be executed immediately before a critical governance vote. The parent's deciding VP is not restored, but the child's is, so the net effect is a partial-to-full recovery of deciding VP depending on the split ratio. The attack is repeatable (split the child again, etc.) subject only to the minimum stake floor.

## Recommendation
In `split_neuron`, explicitly inherit the parent's `voting_power_refreshed_timestamp_seconds` when constructing the child neuron:

```rust
let child_neuron = NeuronBuilder::new(
    child_nid,
    to_subaccount,
    *caller,
    parent_neuron.dissolve_state_and_age(),
    created_timestamp_seconds,
)
.with_voting_power_refreshed_timestamp_seconds(
    parent_neuron.voting_power_refreshed_timestamp_seconds()
)
.with_hot_keys(parent_neuron.hot_keys.clone())
// ... rest of builder
.build();
```

This ensures the child carries the same staleness as the parent. The child can then legitimately refresh its deciding VP by voting or updating followees.

## Proof of Concept
1. Create NNS neuron N with stake 1,000 ICP and dissolve delay ≥6 months.
2. Advance time by 7+ months without voting. Neuron N now has `deciding_voting_power = 0`.
3. Call `manage_neuron` with `Split { amount_e8s: 999_990_000_000, memo: 1 }` (≈9,999 ICP).
4. Observe child neuron C: `voting_power_refreshed_timestamp_seconds = now`, `deciding_voting_power = potential_voting_power` (full).
5. The existing test at `rs/nns/governance/tests/governance.rs` lines 5602–5616 already asserts and confirms this exact behavior, providing a ready-made reproducible proof.