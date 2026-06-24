Audit Report

## Title
`spawn_neuron` Minimum-Stake Guard Uses Stale −5 % Worst-Case While Mission 70 Modulation Floor Is −10 % — (`rs/nns/governance/src/governance.rs`)

## Summary

`spawn_neuron` validates maturity sufficiency by assuming a worst-case modulation of −5 %, hardcoded as `1_f64 - 0.05`. After the Mission 70 switchover (Proposal 141779), the actual modulation floor is −10 % (`MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70 = -1_000`). Any neuron holder can spawn a neuron with maturity in the range `[min_stake / 0.90, min_stake / 0.95)`, pass the guard, and have `maybe_spawn_neurons` mint a stake below `neuron_minimum_stake_e8s`, violating the NNS governance accounting invariant.

## Finding Description

**Root cause — hardcoded −5 % guard in `spawn_neuron`:** [1](#0-0) 

The constant `0.05` was correct under the old CMC-polled range (`MIN_MATURITY_MODULATION_PERMYRIAD = -500` in `rs/nervous_system/governance/src/maturity_modulation/mod.rs`). [2](#0-1) 

**Mission 70 extends the floor to −10 %:** [3](#0-2) 

**CHANGELOG confirms the live switchover (Proposal 141779):** [4](#0-3) 

**`maybe_spawn_neurons` now reads the Mission 70 modulation field and passes it directly to `apply_maturity_modulation`:** [5](#0-4) [6](#0-5) 

The minted stake is then written directly to `cached_neuron_stake_e8s`: [7](#0-6) 

**The gap:** The guard at spawn time uses −5 %, but the modulation applied at minting time can be −10 %. For any maturity `M` satisfying `M × 0.95 ≥ min_stake > M × 0.90`, the guard passes but the minted stake falls below `neuron_minimum_stake_e8s`.

## Impact Explanation

Neurons are created on-chain with `cached_neuron_stake_e8s < neuron_minimum_stake_e8s`, incrementing `neurons_with_invalid_stake_count` in NNS governance metrics. [8](#0-7) 

Such neurons may be ineligible to vote or participate in governance proposals, silently shrinking the effective voting pool. The ICP is not permanently destroyed (the neuron can be dissolved and funds retrieved), but the NNS governance accounting invariant — that every spawned neuron holds at least `neuron_minimum_stake_e8s` — is concretely violated. This matches the **High** impact class: significant NNS security impact with concrete user and protocol harm (voting eligibility loss, governance state corruption).

## Likelihood Explanation

- **Trigger condition 1**: ICP price must be persistently below its 365-day moving average, driving `compute_maturity_modulation_permyriad` toward −1000 permyriad. This is a realistic bear-market condition, not a contrived scenario.
- **Trigger condition 2**: Maturity must fall in the window `[min_stake / 0.90, min_stake / 0.95)`. With `neuron_minimum_stake_e8s = 100_000_000` e8s (1 ICP), this is roughly 1.00–1.11 ICP of maturity — easily reachable by any active voter.
- **Entry path**: `spawn_neuron` is a standard unprivileged `manage_neuron` ingress call. No special role, key, or governance majority is required.

## Recommendation

Replace the hardcoded `0.05` in `spawn_neuron` with the actual Mission 70 minimum modulation constant, using `apply_maturity_modulation` for consistency with the minting path:

```rust
// rs/nns/governance/src/governance.rs
use crate::timer_tasks::update_icp_xdr_rate_related_data::MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70;
use ic_nervous_system_governance::maturity_modulation::apply_maturity_modulation;

let least_possible_stake = apply_maturity_modulation(
    maturity_to_spawn,
    MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70 as i32,
).unwrap_or(0);

if least_possible_stake < economics.neuron_minimum_stake_e8s {
    return Err(GovernanceError::new_with_message(
        ErrorType::InsufficientFunds,
        "There isn't enough maturity to spawn a new neuron due to worst case maturity modulation.",
    ));
}
```

This makes the guard at spawn time consistent with the modulation actually applied at minting time.

## Proof of Concept

1. Assume `neuron_minimum_stake_e8s = 100_000_000` e8s (1 ICP).
2. ICP price enters a sustained bear market; `compute_maturity_modulation_permyriad` converges to −1000 permyriad over time (capped by `MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70`).
3. User calls `spawn_neuron` with `maturity_to_spawn = 106_000_000` e8s (~1.06 ICP).
4. Guard check: `106_000_000 × 0.95 = 100_700_000 ≥ 100_000_000` → **passes**.
5. Neuron enters spawning state (`spawn_at_timestamp_seconds` set, 7-day delay).
6. `maybe_spawn_neurons` fires; reads `maturity_modulation = -1000` from `heap_data.maturity_modulation.current_value_permyriad`.
7. `apply_maturity_modulation(106_000_000, -1000)` = `106_000_000 × 9_000 / 10_000 = 95_400_000` e8s.
8. `cached_neuron_stake_e8s` is set to `95_400_000 < 100_000_000 = neuron_minimum_stake_e8s`.
9. The neuron is created on-chain with an invalid (below-minimum) stake; `neurons_with_invalid_stake_count` increments.

A deterministic integration test can reproduce this by: (a) setting `heap_data.maturity_modulation.current_value_permyriad = -1000`, (b) calling `spawn_neuron` with the maturity value above, (c) advancing the mock clock by 7+ days, (d) calling `maybe_spawn_neurons`, and (e) asserting `cached_neuron_stake_e8s < neuron_minimum_stake_e8s`.

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

**File:** rs/nns/governance/src/governance.rs (L6427-6435)
```rust
        let maturity_modulation = match self
            .heap_data
            .maturity_modulation
            .as_ref()
            .and_then(|m| m.current_value_permyriad)
        {
            None => return,
            Some(value) => value,
        };
```

**File:** rs/nns/governance/src/governance.rs (L6484-6502)
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
```

**File:** rs/nns/governance/src/governance.rs (L6509-6521)
```rust
                    let (staked_neuron_clone, original_spawn_at_timestamp_seconds) = self
                        .with_neuron_mut(&neuron_id, |neuron| {
                            // Reset the neuron's maturity and set that it's spawning before we actually mint
                            // the stake. This is conservative to prevent a neuron having _both_ the stake and
                            // the maturity at any point in time.
                            let original_spawn_ts = neuron.spawn_at_timestamp_seconds;
                            neuron.maturity_e8s_equivalent = 0;
                            neuron.spawn_at_timestamp_seconds = None;
                            neuron.cached_neuron_stake_e8s = neuron_stake;

                            (neuron.clone(), original_spawn_ts)
                        })
                        .unwrap();
```

**File:** rs/nervous_system/governance/src/maturity_modulation/mod.rs (L4-5)
```rust
pub const MIN_MATURITY_MODULATION_PERMYRIAD: i32 = -500;
pub const MAX_MATURITY_MODULATION_PERMYRIAD: i32 = 500;
```

**File:** rs/nns/governance/src/timer_tasks/update_icp_xdr_rate_related_data.rs (L46-50)
```rust
/// Lower bound for Mission 70 maturity modulation: -10% = -1000 permyriad.
pub(crate) const MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70: i64 = -1_000;

/// Upper bound for Mission 70 maturity modulation: +2% = 200 permyriad.
pub(crate) const MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70: i64 = 200;
```

**File:** rs/nns/governance/CHANGELOG.md (L14-23)
```markdown
# 2026-05-17: Proposal 141779

http://dashboard.internetcomputer.org/proposal/141779

## Changed

* Neuron spawning and maturity disbursement finalization now read the locally
  computed Mission 70 maturity modulation (derived from the XRC-backed price
  history) instead of the CMC-polled `cached_daily_maturity_modulation_basis_points`.

```

**File:** rs/nns/governance/src/neuron_store/metrics.rs (L35-35)
```rust
    pub(crate) neurons_with_invalid_stake_count: u64,
```
