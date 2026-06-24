Audit Report

## Title
SNS Swap `validate_participation_constraints` Uses Insufficient Denominator in Floor Division, Allowing Swap Configurations Where Participants Receive Fewer SNS Tokens Than Required for Neuron Formation - (File: `rs/sns/init/src/lib.rs`)

## Summary

`validate_participation_constraints` computes the minimum SNS tokens a participant will receive using `max_direct_participation_icp_e8s` as the denominator, but at finalization `create_sns_neuron_recipes` divides by `current_total_participation_e8s()`, which includes Neurons' Fund ICP and is therefore strictly larger whenever NF participates. The validation passes, but the actual per-participant SNS allocation is smaller than assumed, causing `create_sns_neuron_basket_for_direct_participant` to fail. The participant's ICP has already been swept to SNS governance, but no SNS neuron recipes are created for them.

## Finding Description

**Validation denominator (too small):**

In `rs/sns/init/src/lib.rs` at L1636–1638, the minimum SNS tokens a participant will receive is estimated as:

```rust
let min_participant_sns_e8s = min_participant_icp_e8s as u128
    * initial_swap_amount_e8s as u128
    / max_direct_participation_icp_e8s as u128;   // only direct ICP
``` [1](#0-0) 

This is then checked against the neuron basket requirement at L1640–1642:

```rust
let min_participant_icp_e8s_big_enough = min_participant_sns_e8s
    >= neuron_basket_construction_parameters_count as u128
        * (neuron_minimum_stake_e8s + sns_transaction_fee_e8s) as u128;
``` [2](#0-1) 

**Actual swap denominator (larger):**

At finalization, `create_sns_neuron_recipes` computes `total_participant_icp_e8s` from `self.current_total_participation_e8s()` at L818–820, which includes both direct and NF ICP: [3](#0-2) 

This larger value is passed to `Swap::scale` at L848–852:

```rust
let amount_sns_e8s = Swap::scale(
    buyer_state.amount_icp_e8s(),
    sns_being_offered_e8s,
    total_participant_icp_e8s,   // direct + NF
);
``` [4](#0-3) 

`Swap::scale` performs integer (floor) division: [5](#0-4) 

**Failure path:**

When `amount_sns_e8s` is smaller than the validation assumed, `apportion_approximately_equally` (L203–207, floor division) splits it across `neuron_basket_count` neurons, and at least one neuron falls below `neuron_minimum_stake_e8s`. `create_sns_neuron_basket_for_direct_participant` returns `Err`, and the error branch at L872–881 increments `sweep_result.failure` and `continue`s — no neuron recipes are created for that participant: [6](#0-5) 

The same denominator mismatch exists in `Params::validate` in `rs/sns/swap/src/types.rs` at L346–348, which uses `max_icp_e8s` without accounting for NF: [7](#0-6) 

**Concrete PoC arithmetic:**

| Parameter | Value |
|---|---|
| `min_participant_icp_e8s` | 5 |
| `initial_swap_amount_e8s` | 10 |
| `max_direct_participation_icp_e8s` | 7 |
| NF participation | 3 ICP |
| `total_participant_icp_e8s` | 10 |
| `neuron_basket_count` | 2 |
| `neuron_minimum_stake_e8s` | 3 |

Validation: `5 * 10 / 7 = 7 ≥ 2 * 3 = 6` → passes.  
Finalization: `5 * 10 / 10 = 5`; `apportion_approximately_equally(5, 2) = [3, 2]`; neuron[1].stake = 2 < 3 → `Err`, no recipes created.

## Impact Explanation

Direct swap participants who contributed exactly `min_participant_icp_e8s` lose their entire SNS token allocation. Their ICP is irreversibly transferred to SNS governance, but no SNS neuron recipes are ever created for them. This is a concrete, ledger-level loss of user funds within the SNS framework — matching the **High** impact class: "Significant SNS security impact with concrete user or protocol harm."

## Likelihood Explanation

The conditions are: (1) `neurons_fund_participation = true` (common in SNS swaps), (2) `min_participant_icp_e8s` set at or near the boundary value that just passes `validate_participation_constraints`, and (3) NF actually participates at finalization. NF participation is determined automatically by NNS governance at finalization time, not at initialization, so an SNS creator cannot prevent it after the swap opens. Any participant who contributes exactly `min_participant_icp_e8s` in such a swap is affected without any further action on their part.

## Recommendation

The denominator in `validate_participation_constraints` must use the maximum possible total ICP, including NF:

```rust
// rs/sns/init/src/lib.rs
let max_total_participation_icp_e8s = max_direct_participation_icp_e8s
    .saturating_add(max_neurons_fund_participation_icp_e8s.unwrap_or(0));

let min_participant_sns_e8s = min_participant_icp_e8s as u128
    * initial_swap_amount_e8s as u128
    / max_total_participation_icp_e8s as u128;
```

The same fix must be applied to `Params::validate` in `rs/sns/swap/src/types.rs` at L346–348, replacing `max_icp_e8s` with the total including NF.

## Proof of Concept

1. Initialize an SNS with `neurons_fund_participation = true`, `min_participant_icp_e8s = 5`, `max_direct_participation_icp_e8s = 7`, `initial_swap_amount_e8s = 10`, `neuron_basket_count = 2`, `neuron_minimum_stake_e8s = 3`. Initialization passes `validate_participation_constraints`.
2. Swap opens. A direct participant calls `refresh_buyer_tokens` contributing exactly 5 ICP e8s.
3. NNS governance triggers NF participation of 3 ICP e8s, making `current_total_participation_e8s() = 10`.
4. Swap commits. `create_sns_neuron_recipes` is called. `Swap::scale(5, 10, 10) = 5`.
5. `apportion_approximately_equally(5, 2)` returns `[3, 2]`. The second neuron has stake 2 < `neuron_minimum_stake_e8s` (3).
6. `create_sns_neuron_basket_for_direct_participant` returns `Err`. `sweep_result.failure += 2`. No neuron recipes created.
7. The participant's 5 ICP e8s have already been swept to SNS governance; they receive zero SNS tokens.

A deterministic unit test in `rs/sns/swap/src/swap.rs` can reproduce this by constructing a `Swap` state with the above parameters, calling `create_sns_neuron_recipes`, and asserting `sweep_result.failure > 0`.

### Citations

**File:** rs/sns/init/src/lib.rs (L1636-1638)
```rust
        let min_participant_sns_e8s = min_participant_icp_e8s as u128
            * initial_swap_amount_e8s as u128
            / max_direct_participation_icp_e8s as u128;
```

**File:** rs/sns/init/src/lib.rs (L1640-1642)
```rust
        let min_participant_icp_e8s_big_enough = min_participant_sns_e8s
            >= neuron_basket_construction_parameters_count as u128
                * (neuron_minimum_stake_e8s + sns_transaction_fee_e8s) as u128;
```

**File:** rs/sns/swap/src/swap.rs (L742-751)
```rust
    fn scale(amount_icp_e8s: u64, total_sns_e8s: u64, total_icp_e8s: NonZeroU64) -> u64 {
        assert!(amount_icp_e8s <= u64::from(total_icp_e8s));
        // Note that the multiplication cannot overflow as both factors fit in 64 bits.
        let r = (amount_icp_e8s as u128)
            .saturating_mul(total_sns_e8s as u128)
            .div(NonZeroU128::from(total_icp_e8s));
        // This follows logically from the initial assert `amount_icp_e8s <= total_icp_e8s`.
        assert!(r <= u64::MAX as u128);
        r as u64
    }
```

**File:** rs/sns/swap/src/swap.rs (L818-821)
```rust
        let total_participant_icp_e8s = match NonZeroU64::try_from(
            self.current_total_participation_e8s(),
        ) {
            Ok(total_participant_icp_e8s) => total_participant_icp_e8s,
```

**File:** rs/sns/swap/src/swap.rs (L848-852)
```rust
            let amount_sns_e8s = Swap::scale(
                buyer_state.amount_icp_e8s(),
                sns_being_offered_e8s,
                total_participant_icp_e8s,
            );
```

**File:** rs/sns/swap/src/swap.rs (L872-881)
```rust
                Err(error_message) => {
                    log!(
                        ERROR,
                        "Error creating a neuron basked for identity {}. Reason: {}",
                        buyer_principal,
                        error_message
                    );
                    sweep_result.failure += neuron_basket_construction_parameters.count as u32;
                    continue;
                }
```

**File:** rs/sns/swap/src/types.rs (L346-348)
```rust
        let min_participant_sns_e8s = self.min_participant_icp_e8s as u128
            * self.sns_token_e8s as u128
            / self.max_icp_e8s as u128;
```
