Audit Report

## Title
Unauthorized Third-Party Caller Can Forge Buyer Confirmation-Text Acceptance and Force-Register Participation in SNS Swap — (`rs/sns/swap/canister/canister.rs`)

## Summary
The `refresh_buyer_tokens` endpoint in the SNS Swap canister resolves the effective buyer principal from the caller-supplied `arg.buyer` field without verifying it matches the authenticated ingress sender. Any unprivileged caller can invoke this endpoint with an arbitrary victim principal and the publicly-readable `confirmation_text`, permanently recording the victim as having accepted the swap's terms of service and locking their already-transferred ICP into the swap's participation ledger — all without the victim's knowledge or consent.

## Finding Description
In `rs/sns/swap/canister/canister.rs` at L130–134, when `arg.buyer` is non-empty the canister unconditionally parses it as the effective buyer with no check that it equals `caller_principal_id()`:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()   // ← any principal accepted
};
```

This `p` is then passed directly to `swap_mut().refresh_buyer_token_e8s(p, arg.confirmation_text, ...)` at L137.

Inside `refresh_buyer_token_e8s` (`rs/sns/swap/src/swap.rs` L1150), `validate_confirmation_text` checks only that the supplied string equals the swap-configured text — it is never tied to the authenticated caller identity. The function then reads the ICP ledger balance of `buyer`'s subaccount (L1153–1163), and at L1285–1288 permanently writes the buyer's participation into `self.buyers`. No guard anywhere in this call chain verifies that the caller is the buyer.

The `RefreshBuyerTokensRequest` proto (`rs/sns/swap/proto/ic_sns_swap/pb/v1/swap.proto` L843–851) documents `buyer` as optional-defaulting-to-caller but imposes no restriction on who may supply it.

**Exploit flow:**
1. SNS swap is `Open` with `confirmation_text = "I agree to the SNS terms"`.
2. Victim Alice transfers ICP to `swap_subaccount(alice_principal)` but has not yet called `refresh_buyer_tokens`.
3. Attacker Eve submits: `refresh_buyer_tokens({ buyer: alice_principal, confirmation_text: Some("I agree to the SNS terms") })`.
4. The canister resolves `p = alice_principal`, reads Alice's balance, validates the text (matches), and records Alice as a committed participant with forged consent.
5. Alice's ICP is now locked in the swap's accepted participation ledger; `error_refund_icp` will not return her funds after the swap closes because her participation was accepted.

## Impact Explanation
This matches the allowed High impact: **"Significant SNS security impact with concrete user or protocol harm."** Two concrete harms result:

- **Confirmation-text forgery**: The swap permanently records that Alice accepted the swap's legal/terms-of-service text, which she never did. This is an integrity violation of the consent mechanism the `confirmation_text` feature was designed to enforce.
- **Forced fund lock-in**: A victim who transferred ICP by mistake and has not yet called `refresh_buyer_tokens` loses the ability to recover funds via `error_refund_icp` once an attacker triggers registration. The victim is committed to the swap outcome without consent.

## Likelihood Explanation
- The endpoint is publicly reachable by any unprivileged ingress sender with zero preconditions beyond the victim having a non-zero ICP balance in their swap subaccount.
- The `confirmation_text` is readable from public swap state — no secret knowledge is required.
- The attack window spans the entire `Open` lifecycle (potentially days to weeks).
- A motivated attacker (e.g., a competing participant wanting to push a borderline swap over its minimum commitment threshold) has clear incentive.

## Recommendation
Enforce that the resolved buyer principal equals the authenticated caller when a non-empty `buyer` field is supplied:

```rust
async fn refresh_buyer_tokens(arg: RefreshBuyerTokensRequest) -> RefreshBuyerTokensResponse {
    let caller = caller_principal_id();
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller
    } else {
        let requested = PrincipalId::from_str(&arg.buyer).unwrap();
        assert_eq!(requested, caller, "buyer field must match the caller");
        requested
    };
    ...
}
```

If third-party notification (calling on behalf of another buyer) is intentionally desired for operational convenience, it must be restricted to swaps with no `confirmation_text` configured, since accepting terms on behalf of another principal is never safe.

## Proof of Concept
A deterministic PocketIC integration test can prove this without mainnet interaction:

1. Deploy an SNS swap canister in `Open` state with `confirmation_text = "I agree"` and `min_participant_icp_e8s = 1`.
2. Fund Alice's swap subaccount (`subaccount = principal_to_subaccount(alice)`) with 10 ICP on the mock ICP ledger.
3. As Eve (a different principal), call `refresh_buyer_tokens({ buyer: alice.to_text(), confirmation_text: Some("I agree") })`.
4. Assert the call succeeds and `swap.buyers[alice].amount_icp_e8s == 10 * 1e8`.
5. Assert Alice never made any call to the swap canister.
6. Assert `error_refund_icp` returns 0 for Alice after the swap closes, confirming her ICP is locked.