Audit Report

## Title
NNS Governance `disburse_neuron` Burns Full `neuron_fees_e8s` Without Accounting for Open Proposals, Causing Irrecoverable ICP Loss - (File: `rs/nns/governance/src/governance.rs`)

## Summary
The NNS Governance `disburse_neuron` function unconditionally burns the entire `neuron_fees_e8s` balance when disbursing a dissolved neuron, without checking whether any portion of those fees corresponds to still-open proposals that could be adopted and refunded. When a proposal subsequently passes, the refund path in `process_proposal` silently no-ops because `neuron_fees_e8s` is already zero. The SNS Governance canister received an explicit fix for this identical bug (Proposal 137687) via `maximum_burnable_fees_for_neuron`, but the NNS Governance canister remains unpatched.

## Finding Description
**Fee charging:** When a neuron submits a non-`ManageNeuron` proposal, `neuron_fees_e8s` is incremented by `proposal_submission_fee` at [1](#0-0) 

**Unconditional burn in `disburse_neuron`:** At disbursement time, the full `fees_amount_e8s` (equal to `neuron.neuron_fees_e8s`) is burned on-ledger with no guard for open proposals, and `neuron_fees_e8s` is then set to `0`: [2](#0-1) 

**Silent refund failure:** When the open proposal is later adopted, `process_proposal` attempts to refund by checking `neuron.neuron_fees_e8s >= rejection_cost`. Since `neuron_fees_e8s` is already `0`, the condition is false and the refund is silently skipped: [3](#0-2) 

**SNS fix absent from NNS:** The SNS `disburse_neuron` calls `maximum_burnable_fees_for_neuron` before burning, which subtracts the sum of `reject_cost_e8s` from all open proposals: [4](#0-3)  The function itself: [5](#0-4)  The SNS then burns only `max_burnable_fee` and decrements `neuron_fees_e8s` by that amount rather than zeroing it: [6](#0-5)  No equivalent guard exists anywhere in the NNS `disburse_neuron` path. The SNS CHANGELOG explicitly documents this as a fixed bug: [7](#0-6) 

## Impact Explanation
A neuron controller permanently loses ICP equal to `reject_cost_e8s` (currently 1 ICP = 100,000,000 e8s) per open proposal at disbursement time. The ICP is burned on the ledger and the governance refund path is permanently bypassed, constituting a concrete ledger conservation violation and irreversible user funds loss within the NNS — a significant NNS governance security impact with concrete user harm. This maps to the **High** severity tier: significant NNS security impact with concrete user or protocol harm.

## Likelihood Explanation
The scenario requires no special privileges: any neuron controller can submit a non-`ManageNeuron` proposal, allow their neuron to dissolve (minimum dissolve delay is sufficient to propose), and call `disburse` before the proposal is decided. The NNS wait-for-quiet mechanism can extend voting periods beyond the base 4-day window, widening the timing overlap. The scenario is accidental-friendly (a controller may not realize their proposal is still open) and requires no adversarial coordination. Likelihood is low but non-zero and fully within normal user behavior.

## Recommendation
Apply the same fix used in SNS Governance. Before burning fees in `disburse_neuron`, compute the maximum burnable amount by summing `reject_cost_e8s` across all open proposals where the neuron is the proposer, subtract that from `fees_amount_e8s`, and burn only the remainder. Update `neuron_fees_e8s` by subtracting the burned amount rather than zeroing it, mirroring the SNS pattern at `rs/sns/governance/src/governance.rs` L1208.

## Proof of Concept
1. Create neuron N with `dissolve_delay = NEURON_MINIMUM_DISSOLVE_DELAY_TO_PROPOSE_SECONDS + 5 days` in `Dissolving` state.
2. After the minimum delay elapses, N has 5 days remaining. N submits a `Motion` proposal. `neuron_fees_e8s` becomes `reject_cost_e8s` (1 ICP).
3. After 5 more days, N enters `Dissolved` state. The proposal's voting period is extended by wait-for-quiet and remains `Open`.
4. N's controller calls `manage_neuron` → `Disburse`. `disburse_neuron` reads `fees_amount_e8s = 1 ICP`, burns it via ledger transfer, sets `neuron_fees_e8s = 0`.
5. The proposal passes. `process_proposal` evaluates `neuron.neuron_fees_e8s >= rejection_cost` → `0 >= 100_000_000` → false. No refund is issued. 1 ICP is permanently destroyed.

This can be reproduced as a deterministic unit test using a mock ledger and mock environment, advancing time to trigger each state transition, and asserting that the neuron controller's final ICP balance is lower than expected by `reject_cost_e8s`.

### Citations

**File:** rs/nns/governance/src/governance.rs (L2046-2074)
```rust
        if fees_amount_e8s > transaction_fee_e8s {
            let now = self.env.now();
            tla_log_label!("DisburseNeuron_Fee");
            tla_log_locals! {
                fees_amount: fees_amount_e8s,
                neuron_id: id.id,
                to_account: tla::account_to_tla(to_account),
                disburse_amount: disburse_amount_e8s
            };
            let _result = self
                .ledger
                .transfer_funds(
                    fees_amount_e8s,
                    0, // Burning transfers don't pay a fee.
                    Some(neuron_subaccount),
                    governance_minting_account(),
                    now,
                )
                .await?;
        }

        self.with_neuron_mut(id, |neuron| {
            // Update the stake and the fees to reflect the burning above.
            if neuron.cached_neuron_stake_e8s > fees_amount_e8s {
                neuron.cached_neuron_stake_e8s -= fees_amount_e8s;
            } else {
                neuron.cached_neuron_stake_e8s = 0;
            }
            neuron.neuron_fees_e8s = 0;
```

**File:** rs/nns/governance/src/governance.rs (L3752-3761)
```rust
        if !proposal.is_manage_neuron()
            && let Some(nid) = proposal.proposer
        {
            let rejection_cost = proposal.reject_cost_e8s;
            self.with_neuron_mut(&nid, |neuron| {
                if neuron.neuron_fees_e8s >= rejection_cost {
                    neuron.neuron_fees_e8s -= rejection_cost;
                }
            })
            .ok();
```

**File:** rs/nns/governance/src/governance.rs (L5356-5358)
```rust
        self.with_neuron_mut(proposer_id, |neuron| {
            neuron.neuron_fees_e8s += proposal_submission_fee;
        })
```

**File:** rs/sns/governance/src/governance.rs (L1156-1156)
```rust
        let max_burnable_fee = self.maximum_burnable_fees_for_neuron(neuron)?;
```

**File:** rs/sns/governance/src/governance.rs (L1181-1208)
```rust
        if max_burnable_fee > transaction_fee_e8s {
            let _result = self
                .ledger
                .transfer_funds(
                    max_burnable_fee,
                    0, // Burning transfers don't pay a fee.
                    Some(from_subaccount),
                    self.governance_minting_account(),
                    self.env.now(),
                )
                .await?;

            // We only update the cached_neuron_stake_e8s and neuron_fees_e8s if we actually
            // burn fees, otherwise this leads to ledger and governance getting out of sync.
            let nid = id.to_string();
            let neuron = self
                .proto
                .neurons
                .get_mut(&nid)
                .expect("Expected the parent neuron to exist");

            // Update the neuron's stake and management fees to reflect the burning
            // above.
            neuron.cached_neuron_stake_e8s = neuron
                .cached_neuron_stake_e8s
                .saturating_sub(max_burnable_fee);

            neuron.neuron_fees_e8s = neuron.neuron_fees_e8s.saturating_sub(max_burnable_fee);
```

**File:** rs/sns/governance/src/governance.rs (L1243-1268)
```rust
    fn maximum_burnable_fees_for_neuron(&self, neuron: &Neuron) -> Result<u64, GovernanceError> {
        let neuron_id = neuron.id.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(ErrorType::NotFound, "Neuron does not have an ID")
        })?;

        // Calculate the total reject costs from all open proposals submitted by this neuron
        let total_open_proposal_reject_costs = self
            .proto
            .proposals
            .values()
            .filter(|proposal_data| {
                // Only consider open proposals where this neuron is the proposer
                proposal_data.proposer.as_ref() == Some(neuron_id)
                    && proposal_data.status() == ProposalDecisionStatus::Open
            })
            .map(|proposal_data| proposal_data.reject_cost_e8s)
            .sum::<u64>();

        // The maximum burnable amount is the total fees minus any fees that are
        // tied up in open proposals (which could potentially be refunded)
        let max_burnable = neuron
            .neuron_fees_e8s
            .saturating_sub(total_open_proposal_reject_costs);

        Ok(max_burnable)
    }
```

**File:** rs/sns/governance/CHANGELOG.md (L89-93)
```markdown
Fixed multiple issues in `disburse_neuron` functionality:

- Fixed a bug that could allow an SNS Neuron to burn fees that would have been refunded after proposal acceptance.
- Fees are now only recorded as burned when they exceed the transaction fee threshold and are actually burned.
- Added comprehensive tests to ensure the correct behavior in the future.
```
