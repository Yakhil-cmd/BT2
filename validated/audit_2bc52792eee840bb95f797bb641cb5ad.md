Audit Report

## Title
Partial Maturity Disbursement Can Leave Sub-Minimum Dust Permanently Undisburse-able - (File: rs/nns/governance/src/governance/disburse_maturity.rs)

## Summary
`initiate_maturity_disbursement` validates only that the *disbursed* portion meets `MINIMUM_DISBURSEMENT_E8S` (= `E8` = 100,000,000 e8s) but never checks that the *remaining* maturity after the operation is either zero or also at or above the minimum. A neuron controller can choose a percentage that satisfies the pre-check yet leaves a sub-minimum remainder that no subsequent `DisburseMaturity` call can ever disburse, permanently stranding up to ~1 ICP of maturity per neuron. For dissolved neurons the only alternative escape path (`stake_maturity_of_neuron`) is explicitly blocked, making the loss irrecoverable.

## Finding Description
`MINIMUM_DISBURSEMENT_E8S` is set to `E8` at line 45 of `disburse_maturity.rs`. In `initiate_maturity_disbursement`, lines 291–298 compute `disbursement_maturity_e8s = maturity * percentage / 100` and reject the call only if that value is below the minimum. No check is performed on `maturity_e8s_equivalent - disbursement_maturity_e8s`. Lines 317–326 then unconditionally reduce the neuron's maturity by the disbursed amount via `saturating_sub`. After this mutation, if the remainder is in `(0, MINIMUM_DISBURSEMENT_E8S)`, every future `DisburseMaturity` call with any percentage 1–100 will produce a disbursement amount ≤ remainder < `MINIMUM_DISBURSEMENT_E8S` and be rejected by the same guard at lines 293–298. The SNS `disburse_maturity` has the structurally identical gap: it checks only the worst-case disbursed amount against `transaction_fee_e8s` (lines 1669–1678 of `rs/sns/governance/src/governance.rs`) without checking the remainder.

**Concrete exploit path:**
1. Neuron has `maturity_e8s_equivalent = 150_000_000`.
2. Controller calls `DisburseMaturity { percentage_to_disburse: 67 }`.
3. `disbursement_maturity_e8s = 150_000_000 * 67 / 100 = 100_500_000 ≥ E8` → check passes.
4. Neuron maturity is set to `49_500_000`.
5. Any subsequent call: max disbursable = `49_500_000 * 100 / 100 = 49_500_000 < E8` → permanently rejected.

## Impact Explanation
Up to `MINIMUM_DISBURSEMENT_E8S − 1 = 99_999_999 e8s` (≈ 1 ICP) of maturity per neuron can be permanently stranded. For dissolved neurons, `stake_maturity_of_neuron` is explicitly blocked (governance.rs ~L2775–2780), leaving no recovery path. This constitutes a moderate, permanent user-funds loss within NNS governance — matching the Medium bounty tier: "moderate user-funds/security impact" in an in-scope NNS canister.

## Likelihood Explanation
Any neuron controller whose maturity is in the range `(MINIMUM_DISBURSEMENT_E8S, 2 × MINIMUM_DISBURSEMENT_E8S)` — i.e., between 1 ICP and 2 ICP — can trigger this with a single `manage_neuron → DisburseMaturity` call. No privileged role is required. The operation is permissionless and the triggering condition (maturity in that range) is common for small stakers. The user need not intend harm; a routine partial disbursement at any percentage that leaves a sub-minimum remainder suffices.

## Recommendation
After computing `disbursement_maturity_e8s` and before mutating the neuron, add:

```rust
let remaining = maturity_e8s_equivalent.saturating_sub(disbursement_maturity_e8s);
if remaining > 0 && remaining < MINIMUM_DISBURSEMENT_E8S {
    return Err(InitiateMaturityDisbursementError::DisbursementTooSmall {
        disbursement_maturity_e8s: remaining,
        minimum_disbursement_e8s: MINIMUM_DISBURSEMENT_E8S,
    });
}
```

Apply the same post-condition to SNS `disburse_maturity`, checking the remainder against `transaction_fee_e8s`.

## Proof of Concept
Unit test plan (safe, local, no mainnet interaction):

1. Create a `NeuronStore` with a single neuron having `maturity_e8s_equivalent = 150_000_000`.
2. Call `initiate_maturity_disbursement` with `percentage_to_disburse = 67`.
3. Assert `Ok(100_500_000)` is returned and neuron maturity is now `49_500_000`.
4. Call `initiate_maturity_disbursement` again with `percentage_to_disburse = 100`.
5. Assert `Err(InitiateMaturityDisbursementError::DisbursementTooSmall { disbursement_maturity_e8s: 49_500_000, minimum_disbursement_e8s: 100_000_000 })`.
6. Repeat step 4–5 for all percentages 1–99; all must return the same error, confirming the maturity is permanently stranded.

This test can be added directly to `rs/nns/governance/src/governance/disburse_maturity_tests.rs` using the existing test infrastructure.