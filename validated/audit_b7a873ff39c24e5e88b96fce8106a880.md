Audit Report

## Title
Missing Anonymous Principal Validation in SNS Swap `refresh_buyer_tokens` Allows State Corruption and Premature Swap Commitment - (File: `rs/sns/swap/canister/canister.rs`)

## Summary
The `refresh_buyer_tokens` handler in `rs/sns/swap/canister/canister.rs` resolves the buyer principal without rejecting the anonymous principal (`2vxsx-fae`). An unprivileged caller can insert a `BuyerState` entry keyed by the anonymous principal into the `buyers` map, inflating `direct_participation_icp_e8s`, consuming one participant slot, and — if the inflated total crosses `min_direct_participation_icp_e8s` — forcing the swap to commit prematurely, converting legitimate participants' ICP into SNS tokens when they expected a refund. In aborted swaps, the anonymous principal's ICP is swept to the uncontrolled anonymous default account and is permanently unrecoverable.

## Finding Description
**Root cause — canister.rs L130–134:**
```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()
};
```
`PrincipalId::from_str("2vxsx-fae")` succeeds; the result is passed directly to `refresh_buyer_token_e8s` with no anonymous-principal guard anywhere in the call chain (confirmed: the only occurrence of "anonymous" in `rs/sns/swap/src/swap.rs` is not a guard).

**State insertion — swap.rs L1285–1291:**
```rust
self.buyers
    .entry(buyer.to_string())
    .or_insert_with(|| BuyerState::new(0))
    .set_amount_icp_e8s(new_balance_e8s);
self.update_total_participation_amounts();
```
A `BuyerState` for `"2vxsx-fae"` is inserted and `direct_participation_icp_e8s` is updated. If this inflated total meets `min_direct_participation_icp_e8s`, the swap transitions to Committed on the next finalization tick, locking all legitimate participants' ICP into SNS tokens.

**sweep_icp — swap.rs L2083–2094:**
```rust
let dst = if lifecycle == Lifecycle::Committed {
    Account { owner: sns_governance.get().0, subaccount: None }
} else {
    Account { owner: principal.0, subaccount: None }  // anonymous account in Aborted case
};
```
In the **Aborted** lifecycle the anonymous principal's ICP is transferred to `Account { owner: anonymous_principal, subaccount: None }` — an account with no controlling key — making those funds permanently unrecoverable. In the **Committed** lifecycle the ICP goes to SNS governance, but the anonymous principal receives SNS neuron baskets it cannot control, producing invalid neuron recipes that increment the `invalid` counter in finalization accounting.

**Participant cap — swap.rs L1181–1197:** The anonymous entry counts toward `MAX_NEURONS_FOR_DIRECT_PARTICIPANTS`, consuming one legitimate participant slot permanently.

**Note on the claim's "repeated draining" assertion:** Because the `buyers` map is keyed by principal string, only a single entry for `"2vxsx-fae"` can exist. The claim's assertion that slots can be exhausted repeatedly via the anonymous principal is incorrect; only one slot is consumed. The fund-loss-in-committed-swap claim is also incorrect: in the Committed lifecycle, ICP goes to SNS governance, not to the anonymous account. These overstatements do not invalidate the core vulnerability.

## Impact Explanation
This matches **High ($2,000–$10,000)**: "Significant SNS security impact with concrete user or protocol harm." An attacker can force a swap to commit prematurely by depositing ICP to the anonymous subaccount and calling `refresh_buyer_tokens`, causing legitimate participants to receive SNS tokens when they expected their ICP returned (swap abort). In aborted swaps, the anonymous principal's ICP is permanently lost to an uncontrolled account. SNS swap is explicitly in scope as a core SNS canister.

## Likelihood Explanation
Triggerable by any unprivileged ingress caller. The attacker only needs to transfer ICP (≥ `min_participant_icp_e8s`) to the anonymous principal's subaccount of the swap canister and call the public `#[update]` endpoint `refresh_buyer_tokens` with `buyer = "2vxsx-fae"`. No governance majority, no privileged access, and no threshold corruption is required. The premature-commitment variant requires the attacker to bridge the gap between current participation and `min_direct_participation_icp_e8s`, which is a real cost but not a prohibitive one for a motivated attacker targeting a specific SNS launch.

## Recommendation
Add an explicit anonymous-principal rejection at the top of `refresh_buyer_token_e8s` (or in the canister handler before calling it):
```rust
if buyer == PrincipalId::new_anonymous() {
    return Err("Anonymous principal cannot participate in the swap".to_string());
}
```
Apply the same guard in `error_refund_icp` to prevent any residual anonymous-subaccount balance from being swept to the uncontrolled anonymous account. The canister handler should also reject an anonymous `caller_principal_id()` in the `arg.buyer.is_empty()` branch.

## Proof of Concept
1. During an open SNS swap, call the ICP ledger `transfer` to send `min_participant_icp_e8s` ICP to `Account { owner: swap_canister_id, subaccount: Some(principal_to_subaccount(anonymous_principal)) }`.
2. Call `refresh_buyer_tokens({ buyer: "2vxsx-fae", confirmation_text: None })` on the swap canister.
3. Observe that `self.buyers` now contains an entry for `"2vxsx-fae"` and `direct_participation_icp_e8s` is inflated.
4. **Aborted-swap fund loss**: Allow the swap to abort; call `finalize_swap`; observe `sweep_icp` transfers the anonymous principal's ICP to `Account { owner: anonymous_principal, subaccount: None }` — confirmed unrecoverable.
5. **Premature commitment**: If the deposited amount bridges the gap to `min_direct_participation_icp_e8s`, observe the swap commits on the next `finalize_swap` call, converting all legitimate participants' ICP to SNS tokens.
6. A deterministic PocketIC integration test can reproduce both scenarios by controlling the swap lifecycle and asserting the final `buyers` map state and ICP ledger balances.