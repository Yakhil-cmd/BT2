Audit Report

## Title
`spawn_neuron` Pre-flight Guard Uses Stale 5% Worst-Case Modulation While Mission 70 Settlement Applies −10% - (File: `rs/nns/governance/src/governance.rs`)

## Summary
`Governance::spawn_neuron` validates the minimum stake using a hardcoded 5% worst-case modulation constant, but `maybe_spawn_neurons` settles spawning neurons using the Mission 70 modulation system whose lower bound is −10%. Any neuron holder with maturity in the window `[neuron_minimum_stake_e8s / 0.95, neuron_minimum_stake_e8s / 0.90)` can initiate a spawn that passes the pre-flight check, irrevocably moves maturity to a child neuron in spawning state, and 7 days later mints a stake below `neuron_minimum_stake_e8s`, violating the protocol's neuron-stake invariant.

## Finding Description
**Pre-flight check (spawn_neuron, line 2666):**
```rust
let least_possible_stake = (maturity_to_spawn as f64 * (1_f64 - 0.05)) as u64;
```
This hardcodes 5% as the worst-case modulation. This constant was correct for the old CMC-based system (`MIN_MATURITY_MODULATION_PERMYRIAD = -500` permyriad = −5% in `rs/nervous_system/governance/src/maturity_modulation/mod.rs` line 4).

**Settlement range (update_icp_xdr_rate_related_data.rs, lines 47–50):**
```rust
pub(crate) const MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70: i64 = -1_000;  // −10%
pub(crate) const MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70: i64 =    200;  // +2%
```

**Settlement validation range (governance.rs, lines 276–278):**
```rust
const VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE: RangeInclusive<i32> =
    MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70 as i32
        ..=MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70 as i32;
```
`maybe_spawn_neurons` accepts any value down to −1000 permyriad as valid.

**Settlement minting (governance.rs, lines 6484–6487):**
```rust
let neuron_stake: u64 = match apply_maturity_modulation(
    original_maturity,
    maturity_modulation,   // can be −1000 permyriad
) {
```

The pre-flight guard at line 2666 checks `M × 0.95 ≥ min_stake`, but settlement at line 6484 applies `M × 0.90` when modulation is −1000 permyriad. Any M satisfying `M × 0.95 ≥ min_stake` and `M × 0.90 < min_stake` passes the guard and produces a sub-minimum neuron. The maturity transfer from parent to child is irrevocable once the spawn is initiated.

## Impact Explanation
This is a **High** severity finding. Any unprivileged NNS neuron holder can permanently move maturity into a spawning child neuron that will be minted below `neuron_minimum_stake_e8s`. This violates the NNS protocol invariant that every neuron must hold at least the minimum stake, constitutes concrete user harm (permanent loss of maturity value relative to the expected minimum-stake neuron), and represents a significant NNS governance integrity issue. The resulting sub-minimum neuron may be unable to participate in governance operations that enforce the minimum stake invariant downstream.

## Likelihood Explanation
Mission 70 modulation starts at 0 and is speed-limited to 30 permyriad/day (`MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD = 30`). Reaching −10% requires approximately 33 consecutive days of ICP price decline relative to the 365-day average — a realistic bear-market scenario. Once modulation is at or near −1000 permyriad, the exploit window is open to any neuron holder whose maturity falls in the vulnerable range. No special privileges are required; the attacker only needs a neuron with maturity in `[min_stake / 0.95, min_stake / 0.90)`.

## Recommendation
Replace the hardcoded `0.05` constant in `spawn_neuron` with the actual Mission 70 lower bound:

```rust
use crate::timer_tasks::update_icp_xdr_rate_related_data::MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70;
use ic_nervous_system_governance::maturity_modulation::apply_maturity_modulation;

let least_possible_stake = apply_maturity_modulation(
    maturity_to_spawn,
    MATURITY_MODULATION_MIN_PERMYRIAD_MISSION_70 as i32,
).unwrap_or(0);
```

This ensures the pre-flight check is consistent with the worst-case value that `maybe_spawn_neurons` will actually apply at settlement time.

## Proof of Concept
1. Set `heap_data.maturity_modulation.current_value_permyriad = Some(-1000)` in a test environment (or wait 33+ days of price decline on mainnet).
2. Obtain `neuron_minimum_stake_e8s` from `NetworkEconomics` (e.g., 100_000_000 e8s = 1 ICP).
3. Call `spawn_neuron` with `maturity_to_spawn = M` where `M × 0.95 ≥ 100_000_000` and `M × 0.90 < 100_000_000` (e.g., M = 105_000_000).
4. Pre-flight check at line 2666: `105_000_000 × 0.95 = 99_750_000 < 100_000_000` — wait, let me recalculate: `105_263_158 × 0.95 = 100_000_000` so use M = 105_300_000: `105_300_000 × 0.95 = 100_035_000 ≥ 100_000_000` ✓ passes; `105_300_000 × 0.90 = 94_770_000 < 100_000_000` ✓ sub-minimum at settlement.
5. Child neuron enters `Spawning` state; parent maturity is permanently reduced by M.
6. After `neuron_spawn_dissolve_delay_seconds` (7 days), `maybe_spawn_neurons` fires, reads `maturity_modulation = −1000`, calls `apply_maturity_modulation(105_300_000, −1000)` → minted stake = 94_770_000 < 100_000_000 = `neuron_minimum_stake_e8s`.
7. The resulting neuron violates the minimum-stake invariant with no recovery path.