Audit Report

## Title
Any Deployed SNS Swap Canister Can Force-Abort Another SNS's Neurons' Fund Settlement - (File: `rs/nns/governance/src/governance.rs`)

## Summary
`settle_neurons_fund_participation` authorizes callers by checking only that the caller is *any* registered SNS swap canister, never that it is the swap canister *associated with the proposal being settled*. A malicious SNS swap canister can call this function with a victim SNS's `nns_proposal_id` and `result = Aborted`, permanently preventing the victim SNS from receiving its Neurons' Fund ICP contribution. The code itself acknowledges the gap with the comment: *"Note that a Swap could settle each other's participation."*

## Finding Description
The authorization logic in `settle_neurons_fund_participation` performs two checks:

1. Verifies the proposal action is `CreateServiceNervousSystem`.
2. Calls `is_canister_id_valid_swap_canister_id`, which queries SNS-W for all deployed SNS instances and returns `Ok` if the caller matches *any* swap canister in that list. [1](#0-0) 

`is_canister_id_valid_swap_canister_id` iterates over all deployed SNS instances and returns `Ok` if the caller matches any of them — it has no knowledge of which proposal is being settled: [2](#0-1) 

At no point is `caller` compared to the swap canister ID stored in the proposal's SNS deployment record. The function is also idempotent: once settled, subsequent calls return the previously stored result without re-checking the caller: [3](#0-2) 

Additionally, in the `Committed` path, `sns_governance_canister_id` is taken directly from the caller-supplied `request.swap_result` and passed to `mint_to_sns_governance` without validation against the proposal's stored SNS canister IDs: [4](#0-3) 

## Impact Explanation
A malicious SNS swap canister (Swap A) can call `settle_neurons_fund_participation` targeting Swap B's `nns_proposal_id` with `result = Aborted`. This immediately refunds all Neurons' Fund maturity reserved for Swap B back to NF neurons and permanently records the `Aborted` state. When Swap B's legitimate swap canister later calls with `Committed`, it hits the idempotency path and receives the already-stored `Aborted` result — it cannot override it. Swap B's SNS treasury receives zero Neurons' Fund ICP, constituting a direct, irreversible financial loss for all of Swap B's participants. This matches: **High ($2,000–$10,000) — Significant NNS/SNS security impact with concrete user or protocol harm.**

## Likelihood Explanation
The attacker must first deploy a legitimate SNS through NNS governance (requiring a passed NNS proposal). This is a meaningful barrier, but once crossed, the attacker holds a permanently valid swap canister ID and can target any future SNS's Neurons' Fund settlement with a single update call. The vulnerability window is the period between a target SNS's swap ending and its swap canister calling `settle_neurons_fund_participation` — this can be hours to days since `finalize_swap` is triggered externally. The attack requires no privileged key, no social engineering, and no consensus-level corruption.

## Recommendation
- **Short term:** Inside `settle_neurons_fund_participation`, after retrieving `proposal_data`, extract the swap canister ID stored in the proposal's SNS deployment record and assert `caller == stored_swap_canister_id`. Reject with `NotAuthorized` if they differ.
- **Long term:** Store the deployed swap canister ID on `ProposalData` at SNS deployment time (analogous to how `OpenSnsTokenSwap` stored `target_swap_canister_id`). Validate `sns_governance_canister_id` in the `Committed` path against the proposal's stored SNS canister IDs. Add negative-path integration tests asserting that a different valid swap canister cannot settle another SNS's Neurons' Fund participation.

## Proof of Concept
1. Attacker deploys SNS A via NNS governance; SNS A's swap canister ID is now registered in SNS-W.
2. SNS B completes its swap in `Committed` state; its `finalize_swap` has not yet been called.
3. Attacker's SNS A swap canister calls NNS governance `settle_neurons_fund_participation` with `nns_proposal_id` = Swap B's NNS proposal ID and `result = Aborted`.
4. Governance calls `is_canister_id_valid_swap_canister_id` — SNS A's swap canister is in the SNS-W list — check passes.
5. Governance settles Swap B's Neurons' Fund participation as `Aborted`, refunds NF maturity, and stores the result.
6. Swap B's legitimate swap canister later calls `settle_neurons_fund_participation` with `Committed`; governance hits the idempotency branch at line 7166–7174 and returns the already-stored `Aborted` result.
7. Swap B's SNS treasury receives zero Neurons' Fund ICP.

A deterministic integration test can reproduce this using PocketIC: deploy two SNS instances, call `settle_neurons_fund_participation` from SNS A's swap canister with SNS B's proposal ID and `Aborted`, then assert that SNS B's subsequent `Committed` call returns the `Aborted` snapshot and that no ICP was minted to SNS B's governance canister.

### Citations

**File:** rs/nns/governance/src/governance.rs (L7018-7038)
```rust
        // Check authorization. Note that a Swap could settle each other's participation.
        let target_canister_id: CanisterId = caller.try_into().map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "Caller {caller} is not a valid CanisterId and is not authorized to \
                        settle Neuron's Fund participation in a decentralization swap. Err: {err:?}",
                ),
            )
        })?;
        if let Err(err_msg) =
            is_canister_id_valid_swap_canister_id(target_canister_id, &*self.env).await
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "Caller {caller} is not authorized to settle Neurons' Fund \
                    participation in a decentralization swap. Err: {err_msg:?}",
                ),
            ));
        }
```

**File:** rs/nns/governance/src/governance.rs (L7166-7175)
```rust
            (Some(_), Some(_), Some(previously_computed_final_neurons_fund_participation)) => {
                // Ok case I: Return the priorly computed results (this is an idempotent function).
                println!(
                    "{}INFO: settle_neurons_fund_participation was called for a swap \
                        that has already been settled with ProposalId {:?}. Returning without \
                        doing additional work.",
                    LOG_PREFIX, proposal_data.id
                );
                return Ok(previously_computed_final_neurons_fund_participation.into_snapshot());
            }
```

**File:** rs/nns/governance/src/governance.rs (L7249-7273)
```rust
        } else if let SwapResult::Committed {
            sns_governance_canister_id,
            total_neurons_fund_participation_icp_e8s:
                swap_estimated_total_neurons_fund_participation_icp_e8s,
            ..
        } = request.swap_result
        {
            println!(
                "{}INFO: The Neurons' Fund has decided to provide Matched Funding to the \
                SNS created via proposal {:?}, in the amount of {} ICP e8s taken from {} \
                of its neurons. Congratulations!",
                LOG_PREFIX,
                request.nns_proposal_id,
                amount_icp_e8s,
                final_neurons_fund_participation.num_neurons(),
            );

            let mint_icp_result = self
                .mint_to_sns_governance(
                    &request.nns_proposal_id,
                    sns_governance_canister_id,
                    swap_estimated_total_neurons_fund_participation_icp_e8s,
                    amount_icp_e8s,
                )
                .await;
```

**File:** rs/nns/governance/src/governance.rs (L8215-8225)
```rust
    let is_swap = list_deployed_snses_response
        .instances
        .iter()
        .any(|sns| sns.swap_canister_id == Some(target_canister_id.into()));
    if !is_swap {
        return Err(format!(
            "target_swap_canister_id is not the ID of any swap canister known to sns_wasm: {target_canister_id}"
        ));
    }

    Ok(())
```
