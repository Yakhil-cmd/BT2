Audit Report

## Title
Unauthenticated `buyer` Override in `refresh_buyer_tokens` Bypasses Consent Gate and Forces Swap Participation - (File: rs/sns/swap/canister/canister.rs)

## Summary
The `refresh_buyer_tokens` endpoint in the SNS Swap canister accepts an arbitrary `buyer` principal without verifying that the caller matches that principal. Any unprivileged caller can supply a victim's principal as `buyer` along with the publicly readable `confirmation_text`, causing the swap canister to register the victim as a confirmed participant — bypassing the only explicit user-consent gate in the participation flow — and locking their ICP into the swap outcome without their agreement.

## Finding Description
In `rs/sns/swap/canister/canister.rs` at L130–134, the effective buyer principal is resolved as:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()
};
```

When `arg.buyer` is non-empty, `caller_principal_id()` is never consulted. There is no check that `arg.buyer == caller`. The resolved `p` is passed directly to `refresh_buyer_token_e8s` at L137.

Inside `refresh_buyer_token_e8s` (`swap.rs` L1134–1312), the function:
1. Calls `self.validate_confirmation_text(confirmation_text)` at L1150 — the attacker supplies the publicly readable text, so this passes.
2. Reads the ICP balance of `Account { owner: swap_canister, subaccount: principal_to_subaccount(&buyer) }` at L1154–1163.
3. If the balance meets `min_participant_icp_e8s`, inserts the victim into `self.buyers` at L1285–1288.

Once the victim is in `self.buyers` with `transfer_success_timestamp_seconds == 0`, `error_refund_icp` (`swap.rs` L1950–1959) returns a precondition error blocking any refund:

```rust
if let Some(buyer_state) = self.buyers.get(&source_principal_id.to_string()) {
    if let Some(transfer) = &buyer_state.icp
        && transfer.transfer_success_timestamp_seconds == 0
    {
        return ErrorRefundIcpResponse::new_precondition_error(...)
    }
```

No `withdraw`, `cancel`, or `remove_buyer` function exists in the swap canister. The only exit paths are `sweep_icp` during finalization (ABORTED returns ICP; COMMITTED sends ICP to SNS governance and issues SNS tokens to the victim).

The `confirmation_text` is publicly readable from swap state via `get_state`. The proto definition (`swap.proto` L843–851) confirms the field is caller-supplied with no authentication requirement.

## Impact Explanation
This is a **High** severity SNS security impact. An attacker can force a victim's ICP — already deposited in the swap subaccount — into a committed swap outcome without the victim's explicit consent. The `confirmation_text` mechanism is the only user-agreement gate in the participation flow; bypassing it means the victim never consented to the swap terms. If the swap commits, the victim receives SNS tokens instead of their ICP, constituting unauthorized commitment of user funds to a governance/financial outcome. This matches the allowed impact class: "Significant SNS... security impact with concrete user or protocol harm."

## Likelihood Explanation
High. The only precondition is that the victim has transferred ICP to the swap subaccount — a normal, observable on-chain action visible on the public ICP ledger. The attacker requires no special privileges, no private keys, and no admin access. The `confirmation_text` is publicly readable. The attack is executable immediately after observing the victim's ledger transfer, before the victim calls `refresh_buyer_tokens` themselves.

## Recommendation
Add a caller-identity check before accepting a non-empty `buyer` field in `rs/sns/swap/canister/canister.rs`:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    let supplied = PrincipalId::from_str(&arg.buyer).unwrap();
    if supplied != caller_principal_id() {
        panic!("buyer must match caller");
    }
    supplied
};
```

Alternatively, remove the `buyer` field entirely and always derive the principal from `caller_principal_id()`. If third-party dapp delegation is a required use case, it should be gated by an explicit on-chain authorization mechanism rather than an unauthenticated string field.

## Proof of Concept

1. Alice transfers 5 ICP to `Account { owner: swap_canister, subaccount: principal_to_subaccount(alice) }` on the ICP ledger, intending to evaluate participation but not yet ready to commit.
2. Attacker Bob reads `confirmation_text = Some("I agree to the terms")` from the public swap state via `get_state`.
3. Bob calls `refresh_buyer_tokens({ buyer: alice.to_string(), confirmation_text: Some("I agree to the terms") })` from his own principal.
4. The swap canister resolves `p = alice` (L130–134), reads Alice's subaccount balance (5 ICP ≥ `min_participant_icp_e8s`), passes `validate_confirmation_text` (L1150), and inserts Alice into `self.buyers` (L1285–1288).
5. Alice calls `error_refund_icp({ source_principal_id: alice })` — the canister returns `"ICP cannot be refunded as principal alice has 500000000 ICP (e8s) in escrow"` (L1955–1959).
6. The swap commits; Alice's ICP is swept to SNS governance (L2083–2088) and she receives SNS tokens she never consented to purchase.

A deterministic unit test can reproduce this by constructing a `Swap` in `Open` state with `confirmation_text` set, calling `refresh_buyer_token_e8s` with a mismatched caller/buyer pair, and asserting the victim appears in `self.buyers` and `error_refund_icp` returns a precondition error.