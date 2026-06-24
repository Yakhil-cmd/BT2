Audit Report

## Title
Stale Hardcoded -5% Worst-Case Modulation in `spawn_neuron` Allows Sub-Minimum-Stake Neuron Creation Under Mission 70's -10% Range — (File: rs/nns/governance/src/governance.rs)

## Summary

`spawn_neuron` guards against creating a neuron with insufficient stake by computing `maturity_to_spawn * 0.95` as the worst-case stake, encoding the assumption that maturity modulation cannot exceed -5%. Mission 70 expanded the valid NNS modulation range to -10% (`MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70 = -1_000`). `maybe_spawn_neurons` accepts and applies any value in `VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE` (bounded by the Mission 70 constants) without a post-modulation minimum-stake check, so a neuron whose maturity passes the -5% guard can be minted with a stake below `neuron_minimum_stake_e8s` when the actual modulation is between -5% and -10%.

## Finding Description

**Root cause — stale literal in `spawn_neuron`:**

```rust
// rs/nns/governance/src/governance.rs  L2664-2672
let least_possible_stake = (maturity_to_spawn as f64 * (1_f64 - 0.05)) as u64;

if least_possible_stake < economics.neuron_minimum_stake_e8s {
    return Err(GovernanceError::new_with_message(
        ErrorType::InsufficientFunds,
        "There isn't enough maturity to spawn a new neuron due to worst case maturity modulation.",
    ));
}
```

The literal `0.05` encodes -500 permyriad, matching the old `MIN_MATURITY_MODULATION_PERMYRIAD = -500` in `rs/nervous_system/governance/src/maturity_modulation/mod.rs` (L4). Mission 70 introduced a wider NNS-specific range:

```rust
// rs/nns/governance/src/timer_tasks/update_icp_xdr_rate_related_data.rs  L47-50
pub(crate) const MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70: i64 = -1_000;
pub(crate) const MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70: i64 = 200;
```

**Exploit path in `maybe_spawn_neurons`:**

`maybe_spawn_neurons` reads `current_value_permyriad` from `heap_data.maturity_modulation`, validates it against `VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE` (whose log message explicitly references the Mission 70 bounds of `[-1000, 200]`), and then applies it unconditionally:

```rust
// rs/nns/governance/src/governance.rs  L6438-6447
if !VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE.contains(&maturity_modulation) {
    println!(
        "...Should be in range [{}, {}]...",
        MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70,   // -1000
        MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70,   //  200
        ...
    );
    return;
}
```

```rust
// rs/nns/governance/src/governance.rs  L6484-6502
let neuron_stake: u64 = match apply_maturity_modulation(
    original_maturity,
    maturity_modulation,   // can be -1000 permyriad
) { ... };
// ...
neuron.cached_neuron_stake_e8s = neuron_stake;  // set without minimum-stake check
```

`apply_maturity_modulation` in `rs/nervous_system/governance/src/maturity_modulation/mod.rs` (L11-29) computes `amount * (10_000 + basis_points) / 10_000`, so -1000 permyriad yields 90% of the original maturity. No post-modulation check against `neuron_minimum_stake_e8s` exists anywhere in `maybe_spawn_neurons`.

**Existing guard is insufficient:** The only guard is the pre-flight `0.95` multiplier in `spawn_neuron`. Once the child neuron is placed in spawning state, `maybe_spawn_neurons` applies whatever modulation is current without re-validating the resulting stake against the minimum.

## Impact Explanation

Any NNS neuron controller whose `maturity_e8s_equivalent` falls in the window `[neuron_minimum_stake_e8s / 0.95, neuron_minimum_stake_e8s / 0.90)` can call `spawn_neuron` successfully, have a child neuron created in spawning state, and then have `maybe_spawn_neurons` mint a sub-minimum ICP amount to that neuron when the daily modulation is at or near -10%. The result is `cached_neuron_stake_e8s < neuron_minimum_stake_e8s`, violating the core NNS governance invariant that every neuron holds at least the minimum stake. This constitutes a **Significant NNS governance security impact with concrete user harm** — the minted ICP is permanently below the threshold, and the neuron may be in an inconsistent state with respect to downstream governance operations that rely on the minimum-stake invariant (e.g., split, merge, disburse checks). This maps to the **High ($2,000–$10,000)** impact tier.

## Likelihood Explanation

The Mission 70 modulation algorithm (`compute_maturity_modulation_permyriad`) can produce values as low as -1000 permyriad whenever the 7-day ICP price is sufficiently below the 365-day reference price — a realistic sustained-decline market condition. The modulation is updated daily by the NNS timer task. No privileged access is required; `spawn_neuron` is a standard user-callable update callable by any neuron controller. The vulnerable maturity window is approximately 5.3% wide (`1/0.95 - 1/0.90 ≈ 0.053`), meaning any user with maturity in that band is affected whenever modulation reaches -10%.

## Recommendation

Replace the hardcoded literal with the actual Mission 70 minimum constant:

```rust
use crate::timer_tasks::update_icp_xdr_rate_related_data::MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70;

let worst_case_fraction =
    1.0_f64 + (MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70 as f64 / 10_000.0_f64);
let least_possible_stake = (maturity_to_spawn as f64 * worst_case_fraction) as u64;
```

Alternatively, derive the bound from `VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE.start()` so future range changes propagate automatically. Also add a post-modulation minimum-stake check in `maybe_spawn_neurons` before setting `cached_neuron_stake_e8s` as a defense-in-depth measure.

## Proof of Concept

Assume `neuron_minimum_stake_e8s = 100_000_000` (1 ICP).

1. User holds a neuron with `maturity_e8s_equivalent = 106_000_000`.
2. User calls `spawn_neuron` with `percentage_to_spawn = 100`.
3. Guard: `106_000_000 * 0.95 = 100_700_000 ≥ 100_000_000` → **passes** (`spawn_neuron` L2666-2668).
4. Child neuron created in spawning state with `maturity_e8s_equivalent = 106_000_000`.
5. Next daily timer run: `current_value_permyriad = -1_000` (within Mission 70 range, passes L6438 check).
6. `apply_maturity_modulation(106_000_000, -1_000)` = `106_000_000 * 9_000 / 10_000 = 95_400_000`.
7. `neuron.cached_neuron_stake_e8s = 95_400_000 < 100_000_000` — **invariant violated**.
8. Ledger mints 95_400_000 e8s to the child neuron subaccount.

A deterministic integration test using `PocketIc` or the existing NNS governance test harness can reproduce this by: (a) setting `maturity_e8s_equivalent` to a value in the vulnerable window, (b) calling `spawn_neuron`, (c) setting `heap_data.maturity_modulation.current_value_permyriad = -1000`, and (d) calling `maybe_spawn_neurons`, then asserting `cached_neuron_stake_e8s < neuron_minimum_stake_e8s`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rs/nns/governance/src/governance.rs (L2664-2673)
```rust
        // Check if the least possible stake this neuron would be spawned with
        // is more than the minimum neuron stake.
        let least_possible_stake = (maturity_to_spawn as f64 * (1_f64 - 0.05)) as u64;

        if least_possible_stake < economics.neuron_minimum_stake_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                "There isn't enough maturity to spawn a new neuron due to worst case maturity modulation.",
            ));
        }
```

**File:** rs/nns/governance/src/governance.rs (L6437-6447)
```rust
        // Sanity check that the maturity modulation returned is within bounds.
        if !VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE.contains(&maturity_modulation) {
            println!(
                "{}Maturity modulation (in basis points) out-of-bounds. Should be in range [{}, {}], actually is: {}",
                LOG_PREFIX,
                MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70,
                MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70,
                maturity_modulation
            );
            return;
        }
```

**File:** rs/nns/governance/src/governance.rs (L6484-6518)
```rust
                    let neuron_stake: u64 = match apply_maturity_modulation(
                        original_maturity,
                        maturity_modulation,
                    ) {
                        Ok(neuron_stake) => neuron_stake,
                        Err(err) => {
                            // Do not retain the lock so that other Neuron operations can continue.
                            // This is safe as no changes to the neuron have been made to the neuron
                            // both internally to governance and externally in ledger.
                            println!(
                                "{}Could not apply modulation to {:?} for neuron {:?} due to {:?}, skipping",
                                LOG_PREFIX,
                                neuron.maturity_e8s_equivalent,
                                neuron.id(),
                                err
                            );
                            continue;
                        }
                    };

                    println!(
                        "{}Spawning neuron: {:?}. Performing ledger update.",
                        LOG_PREFIX, neuron
                    );

                    let (staked_neuron_clone, original_spawn_at_timestamp_seconds) = self
                        .with_neuron_mut(&neuron_id, |neuron| {
                            // Reset the neuron's maturity and set that it's spawning before we actually mint
                            // the stake. This is conservative to prevent a neuron having _both_ the stake and
                            // the maturity at any point in time.
                            let original_spawn_ts = neuron.spawn_at_timestamp_seconds;
                            neuron.maturity_e8s_equivalent = 0;
                            neuron.spawn_at_timestamp_seconds = None;
                            neuron.cached_neuron_stake_e8s = neuron_stake;

```

**File:** rs/nns/governance/src/timer_tasks/update_icp_xdr_rate_related_data.rs (L46-50)
```rust
/// Lower bound for Mission 70 maturity modulation: -10% = -1000 permyriad.
pub(crate) const MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70: i64 = -1_000;

/// Upper bound for Mission 70 maturity modulation: +2% = 200 permyriad.
pub(crate) const MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70: i64 = 200;
```

**File:** rs/nervous_system/governance/src/maturity_modulation/mod.rs (L4-5)
```rust
pub const MIN_MATURITY_MODULATION_PERMYRIAD: i32 = -500;
pub const MAX_MATURITY_MODULATION_PERMYRIAD: i32 = 500;
```
