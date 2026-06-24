All cited code references are confirmed in the repository. The exploit path is valid:

- Line 7018 confirms the comment acknowledging cross-SNS settling is possible.
- `is_canister_id_valid_swap_canister_id` (lines 8215–8223) only checks membership in the global swap list, not association with the specific proposal.
- The state machine (lines 7112–7186) allows a fresh settlement (Ok case III: `(Some(_), None, None)` with non-terminal lifecycle) for any proposal with `initial_neurons_fund_participation` set.
- `mint_to_sns_governance` (lines 7495–7496) mints directly to the caller-supplied `sns_governance_canister_id` with no cross-validation.
- The lifecycle is set to terminal (line 7235) before minting, permanently blocking the legitimate swap from settling.

---

Audit Report

## Title
Cross-SNS Neurons' Fund Settlement Allows Arbitrary ICP Minting to Attacker-Controlled Address — (`rs/nns/governance/src/governance.rs`)

## Summary

`settle_neurons_fund_participation` authorizes any registered SNS swap canister to settle any CSNS proposal's Neurons' Fund participation. The caller-supplied `sns_governance_canister_id` in the `Committed` result is used directly as the ICP mint destination without being validated against the SNS governance canister actually associated with the target proposal. An attacker controlling one legitimate SNS swap canister can redirect the full Neurons' Fund ICP allocation of a victim SNS proposal to an arbitrary address, while permanently blocking the victim SNS from ever settling its own participation.

## Finding Description

`settle_neurons_fund_participation` performs two independent checks that are never cross-correlated:

**1. Caller authorization** — `is_canister_id_valid_swap_canister_id` (lines 8191–8226) calls `SNS_WASM.list_deployed_snses()` and checks only that the caller appears as *any* swap canister in the global registry. It does not verify the caller is the swap canister associated with the specific `nns_proposal_id` in the request. The comment at line 7018 explicitly acknowledges this: `"Note that a Swap could settle each other's participation."` [1](#0-0) 

**2. Mint destination** — `mint_to_sns_governance` (lines 7467–7515) constructs the ICP ledger destination as `AccountIdentifier::new(sns_governance_canister_id, None)` where `sns_governance_canister_id` is taken verbatim from the attacker-controlled `request.swap_result`. It is never compared against the governance canister ID stored in SNS-W for the proposal being settled. [2](#0-1) 

**3. State machine does not block the attack** — The lifecycle guard at lines 7112–7186 allows settlement when the proposal state is `(Some(_), None, None)` with a non-terminal lifecycle (Ok case III). A victim SNS-2 proposal in `Open` state with `initial_neurons_fund_participation` set satisfies exactly this condition. The lifecycle is then set to terminal at line 7235 *before* minting, permanently preventing the legitimate SNS-2 swap from ever settling. [3](#0-2) 

**4. Attacker-controlled field** — The `Committed.sns_governance_canister_id` field is documented as "This is where the minted ICP will be sent" and is fully supplied by the caller. [4](#0-3) 

## Impact Explanation

An attacker controlling SNS-1's swap canister can mint the full Neurons' Fund participation amount computed for SNS-2's CSNS proposal to an arbitrary address. The minted amount is determined by `initial_neurons_fund_participation` and the attacker-supplied `total_direct_participation_icp_e8s`; setting the latter to the maximum direct participation value maximizes the minted ICP. Active SNS swaps with Neurons' Fund participation routinely involve millions of ICP. Additionally, SNS-2's proposal lifecycle is permanently set to `Committed`, blocking the legitimate swap from ever settling and causing permanent loss of Neurons' Fund participation for SNS-2 participants.

This matches the Critical impact class: **Theft, permanent loss, or illegal minting involving exorbitant ICP/Cycles or in-scope chain-key/ledger assets, especially over $1M** ($10,000–$50,000). [5](#0-4) 

## Likelihood Explanation

Preconditions are realistic and achievable on mainnet:
- At least one legitimate SNS swap must be deployed and registered in SNS-W — true today on mainnet.
- A second CSNS proposal must be in `Open` lifecycle with Neurons' Fund participation enabled — the normal state for any active SNS swap.
- The attacker must control the first SNS's swap canister — achievable by deploying an SNS via a CSNS proposal.

The attack requires no privileged NNS access, no private keys, and no majority corruption. It is executable via a single inter-canister call from the attacker's swap canister to NNS Governance. [6](#0-5) 

## Recommendation

After verifying the caller is a valid swap canister, additionally verify that the caller's canister ID matches the swap canister ID associated with the specific `nns_proposal_id` being settled. This can be done by calling `SNS_WASM.get_deployed_sns_by_proposal_id(nns_proposal_id)` and comparing the returned `swap_canister_id` against `caller`. Similarly, the `sns_governance_canister_id` in the `Committed` message should be validated against the `governance_canister_id` returned by the same SNS-W lookup, rather than being accepted as caller-supplied input. [7](#0-6) 

## Proof of Concept

State-machine test outline:

1. Deploy two SNSes (SNS-1 and SNS-2) via two CSNS proposals, both with Neurons' Fund participation enabled. Both swaps are in `Open` lifecycle. Both proposals have `initial_neurons_fund_participation` set.
2. Attacker (controlling SNS-1's swap canister) calls NNS Governance's `settle_neurons_fund_participation` with:
   - `nns_proposal_id` = proposal ID of SNS-2's CSNS proposal
   - `result = Committed { sns_governance_canister_id = attacker_wallet, total_direct_participation_icp_e8s = max_direct_participation }`
3. `is_canister_id_valid_swap_canister_id` passes because SNS-1's swap canister IS in `list_deployed_snses`.
4. State machine hits Ok case III (`(Some(_), None, None)` with non-terminal lifecycle) — no cross-validation occurs.
5. SNS-2's proposal lifecycle is set to `Committed` (line 7235), blocking future settlement.
6. ICP is minted to `attacker_wallet` (lines 7495–7506).
7. Assert: ICP balance of `attacker_wallet` increases by the Neurons' Fund participation amount.
8. Assert: SNS-2's CSNS proposal lifecycle is now `Committed`, blocking the legitimate SNS-2 swap from settling. [8](#0-7)

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

**File:** rs/nns/governance/src/governance.rs (L7180-7185)
```rust
            (Some(_), None, None) => {
                // Ok case III: This function invocation should compute the Neurons' Fund
                // participation, mint ICP to SNS treasury, refund the leftovers, and return
                // the (newly computed) Neurons' Fund participants.
                // Nothing to do.
            }
```

**File:** rs/nns/governance/src/governance.rs (L7234-7237)
```rust
        // Set the lifecycle of the proposal to avoid interleaving callers.
        proposal_data.set_swap_lifecycle_by_settle_neurons_fund_participation_request_type(
            &request.swap_result,
        );
```

**File:** rs/nns/governance/src/governance.rs (L7266-7273)
```rust
            let mint_icp_result = self
                .mint_to_sns_governance(
                    &request.nns_proposal_id,
                    sns_governance_canister_id,
                    swap_estimated_total_neurons_fund_participation_icp_e8s,
                    amount_icp_e8s,
                )
                .await;
```

**File:** rs/nns/governance/src/governance.rs (L7495-7506)
```rust
        let destination =
            AccountIdentifier::new(sns_governance_canister_id, /* subaccount = */ None);

        let _ = self
            .ledger
            .transfer_funds(
                amount_icp_e8s,
                /* fee_e8s = */ 0, // Because there is no fee for minting.
                /* from_subaccount = */ None,
                destination,
                /* memo = */ 0,
            )
```

**File:** rs/nns/governance/src/governance.rs (L8215-8223)
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
```

**File:** rs/nns/governance/api/src/types.rs (L3547-3555)
```rust
    pub struct Committed {
        /// This is where the minted ICP will be sent.
        pub sns_governance_canister_id: Option<PrincipalId>,
        /// Total amount of participation from direct swap participants.
        pub total_direct_participation_icp_e8s: Option<u64>,
        /// Total amount of participation from the Neurons' Fund.
        /// TODO\[NNS1-2570\]: Ensure this field is set.
        pub total_neurons_fund_participation_icp_e8s: Option<u64>,
    }
```
