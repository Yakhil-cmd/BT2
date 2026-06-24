Audit Report

## Title
Integer Division Truncation in `Swap::scale` Produces Zero-Amount SNS Neuron Recipes, Causing Permanent ICP Loss for Swap Participants — (`rs/sns/swap/src/swap.rs`)

## Summary

`Swap::scale` performs integer division that truncates to zero when a participant's ICP contribution is small relative to total participation. `create_sns_neuron_recipes` performs no zero-check on the result, silently creating neuron recipes with `amount_e8s = 0` and permanently marking the participant as processed. The participant's ICP is swept to SNS governance, but `sweep_sns` fails with `AmountTooSmall` for the zero-amount recipes, halting finalization with the ICP already transferred and no SNS tokens issued.

## Finding Description

**Root cause — `Swap::scale`** (`rs/sns/swap/src/swap.rs`, L742–751):

```rust
fn scale(amount_icp_e8s: u64, total_sns_e8s: u64, total_icp_e8s: NonZeroU64) -> u64 {
    let r = (amount_icp_e8s as u128)
        .saturating_mul(total_sns_e8s as u128)
        .div(NonZeroU128::from(total_icp_e8s));
    r as u64
}
```

When `amount_icp_e8s * total_sns_e8s < total_icp_e8s`, integer division truncates to `0`. [1](#0-0) 

**No zero-check in `create_sns_neuron_recipes`** (L848–870): After calling `Swap::scale`, the result `amount_sns_e8s` is passed directly to `create_sns_neuron_basket_for_direct_participant` without any guard. [2](#0-1) 

**`generate_vesting_schedule(0)` succeeds silently**: `apportion_approximately_equally(0, count)` returns `vec![0; count]` — quotient is `0`, remainder is `0`, no error is returned. Neuron recipes with `amount_e8s = 0` are created and `has_created_neuron_recipes = Some(true)` is set, permanently marking the participant as processed. [3](#0-2) 

**`sweep_sns` fails with `AmountTooSmall`**: `transfer_helper` checks `if amount <= fee { return TransferResult::AmountTooSmall; }`. With `amount_e8s = 0` and any non-zero fee, this returns `AmountTooSmall`, incrementing `sweep_result.invalid`. [4](#0-3) 

**Finalization halts after ICP is already swept**: The finalization order is `sweep_icp` → `settle_neurons_fund_participation` → `create_sns_neuron_recipes` → `sweep_sns`. ICP is transferred to SNS governance before `sweep_sns` runs. When `sweep_sns` returns `invalid > 0`, finalization halts with "Transferring SNS tokens did not complete fully, some transfers were invalid or failed." The ICP is already gone. [5](#0-4) 

**Validation gap in `validate_participation_constraints`** (`rs/sns/init/src/lib.rs`, L1636–1638): The pre-swap validation computes the minimum SNS tokens a participant receives using `max_direct_participation_icp_e8s` as the denominator. However, at finalization the actual denominator is `current_total_participation_e8s()`, which includes Neurons' Fund participation. When NF participation is non-zero, the actual denominator is strictly larger, and the validation's guarantee no longer holds. [6](#0-5) 

`current_total_participation_e8s` explicitly sums direct and NF participation: [7](#0-6) 

The same silent-zero path exists for Neurons' Fund participants in `create_sns_neuron_recipes` (L920–942). [8](#0-7) 

## Impact Explanation

A direct swap participant who contributes ICP loses those funds permanently: their ICP is swept to SNS governance (irreversible for committed swaps), `has_created_neuron_recipes = Some(true)` prevents any retry from re-creating the recipe, and `sweep_sns` permanently marks the recipe as `invalid`. The participant receives zero SNS tokens and zero neurons. This is a concrete, irreversible loss of user funds in the SNS framework — matching **High ($2,000–$10,000): Significant SNS security impact with concrete user or protocol harm**.

## Likelihood Explanation

The triggering condition is `amount_icp_e8s * sns_token_e8s < total_participant_icp_e8s`. This is reachable when:
1. Neurons' Fund participation is enabled and substantial, inflating `total_participant_icp_e8s` well above `max_direct_participation_icp_e8s`.
2. A participant contributes near the minimum allowed ICP amount.
3. The validation in `validate_participation_constraints` passes (using `max_direct_participation_icp_e8s` as denominator) while the finalization computation (using the larger total denominator) produces zero.

No attacker action is required — any legitimate participant contributing the minimum amount in a swap with large NF participation is affected. Likelihood is low but non-zero for swaps with substantial matched NF funding.

## Recommendation

1. **Add a zero-check in `create_sns_neuron_recipes`**: After calling `Swap::scale`, if `amount_sns_e8s == 0`, increment `sweep_result.invalid`, do not call `create_sns_neuron_basket_for_*`, and do not set `has_created_neuron_recipes = Some(true)`. This prevents the ICP sweep from proceeding for that participant (or enables a refund path).

2. **Fix the validation denominator in `validate_participation_constraints`**: Replace `max_direct_participation_icp_e8s` with `max_direct_participation_icp_e8s + max_neurons_fund_participation_icp_e8s` (when NF participation is enabled) to match the actual finalization computation.

## Proof of Concept

Configure a swap with:
- `sns_token_e8s = 1_000_000`
- `min_participant_icp_e8s = 1`
- `max_direct_participation_icp_e8s = 1_000_000`
- NF participation = `2_000_000` e8s (matched funding)

Validation passes: `1 * 1_000_000 / 1_000_000 = 1 ≥ neuron_basket_count * (neuron_minimum_stake_e8s + fee)` (with minimal stake/fee settings).

At finalization: `total_participant_icp_e8s = 1_000_001 + 2_000_000 = 3_000_001`.

For a participant with `amount_icp_e8s = 1`:
```
scale(1, 1_000_000, 3_000_001) = (1 * 1_000_000) / 3_000_001 = 0
```

A unit test can be written directly against `create_sns_neuron_recipes` with these parameters: assert that `sweep_result.invalid > 0` and that the participant's ICP `transfer_success_timestamp_seconds` is set (ICP swept) while no valid SNS neuron recipe with non-zero `amount_e8s` exists for that participant.

### Citations

**File:** rs/sns/swap/src/swap.rs (L163-188)
```rust
    fn generate_vesting_schedule(
        &self,
        total_amount_e8s: u64,
    ) -> Result<Vec<ScheduledVestingEvent>, String> {
        if self.count == 0 {
            return Err(
                "NeuronBasketConstructionParameters.count must be greater than zero".to_string(),
            );
        }

        let dissolve_delay_seconds_list = (0..(self.count))
            .map(|i| i * self.dissolve_delay_interval_seconds)
            .collect::<Vec<u64>>();

        let chunks_e8s = apportion_approximately_equally(total_amount_e8s, self.count)?;
        Ok(dissolve_delay_seconds_list
            .into_iter()
            .zip(chunks_e8s)
            .map(
                |(dissolve_delay_seconds, amount_e8s)| ScheduledVestingEvent {
                    dissolve_delay_seconds,
                    amount_e8s,
                },
            )
            .collect())
    }
```

**File:** rs/sns/swap/src/swap.rs (L487-501)
```rust
    pub fn current_total_participation_e8s(&self) -> u64 {
        let current_direct_participation_e8s = self.current_direct_participation_e8s();
        let current_neurons_fund_participation_e8s = self.current_neurons_fund_participation_e8s();
        current_direct_participation_e8s
            .checked_add(current_neurons_fund_participation_e8s)
            .unwrap_or_else(|| {
                log!(
                    ERROR,
                    "current_direct_participation_e8s ({current_direct_participation_e8s}) \
                    + current_neurons_fund_participation_e8s ({current_neurons_fund_participation_e8s}) \
                    > u64::MAX",
                );
                u64::MAX
            })
    }
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

**File:** rs/sns/swap/src/swap.rs (L848-870)
```rust
            let amount_sns_e8s = Swap::scale(
                buyer_state.amount_icp_e8s(),
                sns_being_offered_e8s,
                total_participant_icp_e8s,
            );

            let Some(buyer_principal) = string_to_principal(buyer_principal) else {
                sweep_result.invalid += neuron_basket_construction_parameters.count as u32;
                continue;
            };
            match create_sns_neuron_basket_for_direct_participant(
                &buyer_principal,
                amount_sns_e8s,
                neuron_basket_construction_parameters,
                NEURON_BASKET_MEMO_RANGE_START,
            ) {
                Ok(direct_participant_sns_neuron_recipes) => {
                    self.neuron_recipes
                        .extend(direct_participant_sns_neuron_recipes);
                    total_sns_tokens_sold_e8s =
                        total_sns_tokens_sold_e8s.saturating_add(amount_sns_e8s);
                    sweep_result.success += neuron_basket_construction_parameters.count as u32;
                    buyer_state.has_created_neuron_recipes = Some(true);
```

**File:** rs/sns/swap/src/swap.rs (L920-942)
```rust
                    let amount_sns_e8s = Swap::scale(
                        neurons_fund_neuron.amount_icp_e8s,
                        sns_being_offered_e8s,
                        total_participant_icp_e8s,
                    );

                    match create_sns_neuron_basket_for_neurons_fund_participant(
                        &controller,
                        hotkeys.principals,
                        neurons_fund_neuron.nns_neuron_id,
                        amount_sns_e8s,
                        neuron_basket_construction_parameters,
                        global_neurons_fund_memo,
                        nns_governance_canister_id.get(),
                    ) {
                        Ok(cf_participants_sns_neuron_recipes) => {
                            sweep_result.success +=
                                neuron_basket_construction_parameters.count as u32;
                            self.neuron_recipes
                                .extend(cf_participants_sns_neuron_recipes);
                            total_sns_tokens_sold_e8s =
                                total_sns_tokens_sold_e8s.saturating_add(amount_sns_e8s);
                            neurons_fund_neuron.has_created_neuron_recipes = Some(true);
```

**File:** rs/sns/swap/src/swap.rs (L2113-2121)
```rust
            let result = icp_transferable_amount
                .transfer_helper(
                    now_fn,
                    DEFAULT_TRANSFER_FEE,
                    Some(subaccount),
                    &dst,
                    icp_ledger,
                )
                .await;
```

**File:** rs/sns/swap/src/types.rs (L612-616)
```rust
        let amount = Tokens::from_e8s(self.amount_e8s);
        if amount <= fee {
            // Skip: amount too small...
            return TransferResult::AmountTooSmall;
        }
```

**File:** rs/sns/init/src/lib.rs (L1636-1642)
```rust
        let min_participant_sns_e8s = min_participant_icp_e8s as u128
            * initial_swap_amount_e8s as u128
            / max_direct_participation_icp_e8s as u128;

        let min_participant_icp_e8s_big_enough = min_participant_sns_e8s
            >= neuron_basket_construction_parameters_count as u128
                * (neuron_minimum_stake_e8s + sns_transaction_fee_e8s) as u128;
```
