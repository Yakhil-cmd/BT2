Audit Report

## Title
Missing Anonymous Principal Validation in SNS Swap `refresh_buyer_tokens` Allows Accounting Corruption and Premature Swap Commitment - (File: `rs/sns/swap/canister/canister.rs`)

## Summary
The SNS Swap canister's `refresh_buyer_tokens` endpoint does not reject the anonymous principal (`2vxsx-fae`). Any unprivileged caller can pass the anonymous principal as the `buyer` field, causing a `BuyerState` entry to be inserted under the anonymous principal key. This inflates `direct_participation_icp_e8s`, can push total participation past the minimum commitment threshold causing premature swap commitment, and permanently consumes one participant slot. In the ABORTED lifecycle, the anonymous principal's ICP is swept to the uncontrolled anonymous account.

## Finding Description
In `rs/sns/swap/canister/canister.rs` L130–134, the handler resolves the buyer principal without any anonymous principal check:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()
};
```

`PrincipalId::from_str("2vxsx-fae")` succeeds and returns the anonymous `PrincipalId`. This is passed directly to `refresh_buyer_token_e8s` in `rs/sns/swap/src/swap.rs`. A grep across all files under `rs/sns/swap/` for `anonymous`, `new_anonymous`, `is_anonymous`, and `2vxsx-fae` returns zero matches in the validation path, confirming no guard exists.

Inside `refresh_buyer_token_e8s` (L1134–1310), the function:
1. Queries the ICP ledger balance for the subaccount derived from the anonymous principal (L1153–1163).
2. If the balance meets `min_participant_icp_e8s`, inserts a `BuyerState` entry keyed by `"2vxsx-fae"` (L1285–1288).
3. Calls `self.update_total_participation_amounts()` (L1291), inflating `direct_participation_icp_e8s`.

The participant cap check at L1180–1197 uses `self.buyers.len()`, so the anonymous entry permanently occupies one slot.

During `sweep_icp` (L2046–2154), when lifecycle is `Aborted`, the destination is:
```rust
Account { owner: principal.0, subaccount: None }
```
For the anonymous principal, this is the anonymous default account — an account with no controlling key. ICP swept there is unrecoverable.

When lifecycle is `Committed`, the anonymous principal's ICP correctly flows to SNS governance (L2083–2088), so no third-party fund loss occurs in that path.

`error_refund_icp` (L1925–2032) also has no anonymous principal check: it transfers from `source_principal_id`'s subaccount to `Account { owner: source_principal_id.0, subaccount: None }` (L1992–1994), which for the anonymous principal is again the uncontrolled anonymous account.

**Important correction to the submitted claim**: Because `self.buyers` is keyed by principal string, the anonymous principal can occupy exactly **one** entry. The claim's assertion that "steps 1–4 can be repeated to exhaust all participant slots" is incorrect — subsequent calls update the existing entry rather than creating new ones. The slot exhaustion impact is therefore limited to one slot.

## Impact Explanation
The concrete impacts are:

1. **Premature swap commitment (High)**: An attacker deposits ICP (up to `max_participant_icp_e8s`) to the anonymous principal's subaccount of the swap canister, then calls `refresh_buyer_tokens`. If total participation was near `min_direct_participation_icp_e8s`, the inflated `direct_participation_icp_e8s` can push it past the minimum threshold. A subsequent `finalize_swap` call then commits the swap. Participants who expected the swap to abort and recover their ICP are instead committed — they receive SNS tokens they did not intend to purchase. This is a concrete SNS security impact with direct user harm.

2. **Participant slot exhaustion (limited DoS)**: One participant slot is permanently consumed, potentially blocking one legitimate participant from joining a near-capacity swap.

3. **Attacker's own ICP burned on abort**: In the ABORTED lifecycle, the attacker's deposited ICP is swept to the anonymous account and is unrecoverable. This is a loss borne by the attacker, not by other users.

This qualifies as a **High** severity SNS security impact: a relatively straightforward attack with meaningful impact on swap outcome and participant funds, matching the "Significant SNS security impact with concrete user or protocol harm" category.

## Likelihood Explanation
The attack is reachable by any unprivileged ingress sender with no special access. The attacker only needs to transfer ICP to the anonymous principal's subaccount of the swap canister (a standard ICP ledger transfer) and call the public `#[update]` endpoint `refresh_buyer_tokens`. The cost is the ICP deposited (which the attacker loses in the abort case). The premature commitment attack is most effective when total participation is close to `min_direct_participation_icp_e8s`.

## Recommendation
Add an explicit anonymous principal check at the top of `refresh_buyer_token_e8s`, or in the canister handler before calling it:

```rust
if buyer == PrincipalId::new_anonymous() {
    return Err("Anonymous principal cannot participate in the swap".to_string());
}
```

Apply the same check in `error_refund_icp` before processing `source_principal_id` to prevent any residual anonymous-subaccount balance from being swept to the uncontrolled anonymous account.

## Proof of Concept
1. Identify a swap canister in the OPEN lifecycle where `direct_participation_icp_e8s` is close to `min_direct_participation_icp_e8s`.
2. Call ICP ledger `transfer` to send `min_participant_icp_e8s` ICP to `Account { owner: swap_canister_id, subaccount: Some(principal_to_subaccount(PrincipalId::new_anonymous())) }`.
3. Call `refresh_buyer_tokens({ buyer: "2vxsx-fae", confirmation_text: None })` on the swap canister.
4. Observe that `get_derived_state` now shows inflated `direct_participation_icp_e8s`.
5. If the inflated amount crosses `min_direct_participation_icp_e8s`, call `finalize_swap` to commit the swap prematurely.
6. Observe that participants who expected an abort are now committed.
7. A unit test can be written against `refresh_buyer_token_e8s` passing `PrincipalId::new_anonymous()` as `buyer` and asserting the function returns `Ok` (demonstrating the missing guard), then asserting `self.buyers.contains_key("2vxsx-fae")`.