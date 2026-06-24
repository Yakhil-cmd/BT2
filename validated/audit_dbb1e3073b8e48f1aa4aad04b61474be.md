Audit Report

## Title
Silent Discard of Neurons' Fund Maturity Refund Failure Causes Permanent Maturity Loss When Neuron Is Disbursed During Active SNS Swap - (File: `rs/nns/governance/src/governance.rs`)

## Summary
When a `CreateServiceNervousSystem` proposal executes, maturity is drawn from Neurons' Fund (NF) neurons and reserved for the SNS swap. If a participating NF neuron is disbursed (removed from the store) during the swap window, the subsequent refund call in `settle_neurons_fund_participation` silently discards the error via `let _ = ...`, permanently destroying the unrefunded maturity with no recovery path.

## Finding Description
**Step 1 – Draw (proposal execution):** `draw_maturity_from_neurons_fund` reduces `maturity_e8s_equivalent` on each participating NF neuron and propagates errors with `?`, so it cannot silently fail. [1](#0-0) 

**Step 2 – Neuron disbursement (user action during swap):** SNS swaps run for days to weeks. During this window, any NF neuron owner can call `disburse`, which removes the neuron from the stable neuron store. No guard checks whether the neuron appears in an active `initial_neurons_fund_participation` snapshot before allowing disbursement.

**Step 3 – Refund silently fails (swap settlement):** `settle_neurons_fund_participation` computes the refund snapshot and calls `refund_maturity_to_neurons_fund`. This internally calls `apply_neurons_fund_snapshot`, which calls `modify_neuron_maturity` for each neuron in the snapshot. [2](#0-1) 

`modify_neuron_maturity` calls `with_stable_neuron_store_mut` → `with_main_part_mut`. If the neuron was disbursed, it no longer exists and a `NeuronStoreError` is returned, collected into `neurons_fund_action_error`, and propagated as `Err(String)`. [3](#0-2) 

Back in `settle_neurons_fund_participation`, this error is **explicitly discarded**: [4](#0-3) 

The developer comment acknowledges the discard ("merely logging the error for human inspection"), but provides no recovery mechanism. Once the neuron is gone, there is no target to credit the maturity to, and no dedicated recovery ledger exists. The maturity is permanently destroyed.

## Impact Explanation
Maturity has direct monetary value — it can be spawned into ICP tokens. The permanently lost amount equals the difference between the reserved (maximum) participation amount and the actual participation amount for the disbursed neuron. For large NF neurons this can be substantial. This is a concrete, irreversible loss of in-scope governance/ledger assets (NNS neuron maturity), matching the **High** impact category: significant NNS/SNS security impact with concrete user funds harm. The loss is bounded per-neuron per-swap but is fully unrecoverable without a governance hotfix that has no on-chain mechanism to execute.

## Likelihood Explanation
Any NF neuron owner can trigger this by disbursing their neuron during an active SNS swap — a standard, unprivileged ingress call. No special privileges, social engineering, or threshold corruption are required. The swap window (days to weeks) provides ample opportunity. The scenario is self-inflicted but the system provides no warning, no lock, and no fallback, making accidental triggering realistic.

## Recommendation
1. **Guard disbursement:** Before allowing a neuron to be fully disbursed, check whether it appears in any active `initial_neurons_fund_participation` snapshot and reject the disbursement (or require NF participation to be settled first).
2. **Propagate or queue the refund error:** Instead of `let _ = ...`, surface the failure so a governance hotfix can restore the maturity, or record the failed refund amount in a dedicated recovery structure that a subsequent NNS proposal can process.
3. **Alternatively**, credit the unrefunded maturity to the neuron owner's principal via a separate ledger transfer rather than silently discarding it.

## Proof of Concept
1. NF neuron N has `maturity_e8s_equivalent = 1_000_000_000`.
2. A `CreateServiceNervousSystem` proposal executes; `draw_maturity_from_neurons_fund` reduces N's maturity to `800_000_000` (reserving `200_000_000` e8s).
3. The SNS swap opens. N's controller calls `disburse` on N. N is removed from the neuron store.
4. The swap commits with only `50_000_000` e8s of actual NF participation from N. The refund snapshot contains `150_000_000` e8s owed back to N.
5. `settle_neurons_fund_participation` calls `refund_maturity_to_neurons_fund` → `apply_neurons_fund_snapshot` → `modify_neuron_maturity`. `with_main_part_mut` returns `NeuronStoreError` (neuron not found). The error is logged and discarded via `let _ = ...`.
6. `150_000_000` e8s of maturity is permanently destroyed. The neuron owner receives no compensation.

A deterministic integration test using PocketIC can reproduce this by: (a) creating an NF neuron, (b) executing a `CreateServiceNervousSystem` proposal, (c) disbursing the NF neuron, (d) calling `settle_neurons_fund_participation` with partial participation, and (e) asserting that total system maturity decreased by more than the actual participation amount.

### Citations

**File:** rs/nns/governance/src/governance.rs (L7348-7359)
```rust
        // If refunding failed for whatever reason, we opt for providing data to the SNS Swap
        // canister, as the ICP were successfully sent to the SNS Governance. Thus, we return
        // normally in this case, merely logging the error for human inspection.
        let _ = neuron_store
            .refund_maturity_to_neurons_fund(&refund)
            .map_err(|err| {
                println!(
                    "{}ERROR while trying to refund Neurons' Fund: {}. \
                    Total refund amount: {} ICP e8s.",
                    LOG_PREFIX, err, total_refund_amount_icp_e8s,
                );
            });
```

**File:** rs/nns/governance/src/governance.rs (L7416-7417)
```rust
        self.neuron_store
            .draw_maturity_from_neurons_fund(&initial_neurons_fund_participation_snapshot)?;
```

**File:** rs/nns/governance/src/neurons_fund.rs (L1914-1935)
```rust
fn apply_neurons_fund_snapshot(
    neuron_store: &mut NeuronStore,
    snapshot: &NeuronsFundSnapshot,
    action: NeuronsFundAction,
) -> Result<(), String> {
    let mut neurons_fund_action_error = vec![];
    for (neuron_id, neuron_delta) in snapshot.neurons().iter() {
        let action_result = neuron_store.modify_neuron_maturity(neuron_id, |old_maturity| {
            action
                .checked_apply(old_maturity, neuron_delta.amount_icp_e8s)
                .map_err(|verb| {
                    let maturity_delta_e8s = neuron_delta.amount_icp_e8s;
                    format!(
                        "u64 overflow while {verb} maturity from {neuron_id:?} \
                            (*kept* original maturity e8s = {old_maturity}; \
                            requested maturity delta e8s = {maturity_delta_e8s})."
                    )
                })
        });
        if let Err(with_neuron_mut_error) = action_result {
            neurons_fund_action_error.push(with_neuron_mut_error.to_string());
        }
```

**File:** rs/nns/governance/src/neuron_store.rs (L818-833)
```rust
    pub fn modify_neuron_maturity(
        &mut self,
        neuron_id: &NeuronId,
        modify: impl FnOnce(u64) -> Result<u64, String>,
    ) -> Result<(), NeuronStoreError> {
        with_stable_neuron_store_mut(|stable_neuron_store| {
            stable_neuron_store
                .with_main_part_mut(*neuron_id, |neuron| -> Result<(), String> {
                    let new_maturity = modify(neuron.maturity_e8s_equivalent)?;
                    neuron.maturity_e8s_equivalent = new_maturity;
                    Ok(())
                })?
                .map_err(|e| NeuronStoreError::InvalidData { reason: e })?;
            Ok(())
        })
    }
```
