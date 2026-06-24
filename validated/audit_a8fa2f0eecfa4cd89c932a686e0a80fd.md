Audit Report

## Title
Unauthorized Third Party Can Force-Commit Victim's ICP Into SNS Swap by Supplying Arbitrary `buyer` Principal - (`rs/sns/swap/canister/canister.rs`)

## Summary

The `refresh_buyer_tokens` endpoint accepts a caller-supplied `buyer` principal without verifying it matches `ic_cdk::caller()`. The sole consent gate — the `confirmation_text` — is a public, on-chain value readable by anyone via `get_init`. Any unprivileged ingress sender can therefore call `refresh_buyer_tokens` on behalf of any victim who has already transferred ICP to their swap subaccount, irrevocably committing that ICP into the swap without the victim's explicit agreement.

## Finding Description

In `rs/sns/swap/canister/canister.rs` lines 127–143, the handler resolves the buyer from the caller-supplied `arg.buyer` field with no caller-equality check:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()   // ← arbitrary principal, no auth
};
```

The downstream `refresh_buyer_token_e8s` (`rs/sns/swap/src/swap.rs` lines 1134–1310) then:

1. Calls `validate_confirmation_text` (lines 1149–1150), which only checks that the supplied string equals the SNS-configured text — it does **not** verify the caller is the buyer. The confirmation text is stored in `init` state and returned by the public `get_init` query.
2. Reads the ICP balance from `principal_to_subaccount(&buyer)` on the swap canister (lines 1153–1163).
3. Permanently records that balance in `self.buyers` under the victim's principal (lines 1285–1291).

The ticket system (lines 1248–1272) is **not** a security gate. The code comment at line 1271 explicitly states: *"If there exists no ticket for the buyer, the payment flow will simply ignore the ticket."* Even when a ticket exists, the attacker's call passes the ticket check as long as the subaccount balance ≥ the ticket amount, and the ticket is then deleted.

`error_refund_icp` is only available after the swap reaches `Aborted` or `Committed` state (lines 1931–1936). If the swap commits, the victim's ICP is swept to the SNS treasury and they receive SNS tokens — there is no recourse.

## Impact Explanation

This is a **High** severity finding matching: *"Significant SNS security impact with concrete user or protocol harm."*

A victim who has transferred ICP to their swap subaccount but has not yet called `refresh_buyer_tokens` (e.g., still reading the confirmation text, or waiting) has their participation forcibly committed by an attacker. The confirmation text — the only mechanism by which a buyer signals informed consent — is rendered meaningless because it is a public value. The victim receives SNS tokens instead of their ICP without ever having explicitly accepted the swap terms. This is irreversible once the swap commits.

## Likelihood Explanation

- No special privileges are required; any ingress sender can call `refresh_buyer_tokens`.
- Both required inputs (victim's principal and confirmation text) are publicly observable on-chain.
- The attack window exists for any buyer who has transferred ICP but not yet called `refresh_buyer_tokens` — a normal intermediate state in the payment flow.
- The ticket-based payment flow does not close this window: a victim who transferred ICP without first creating a ticket (or whose ticket was already consumed) has no protection whatsoever.
- The attack is repeatable across any open SNS swap with a non-empty confirmation text.

## Recommendation

Enforce that the resolved buyer principal equals `ic_cdk::caller()` when a non-empty `buyer` field is supplied. In `rs/sns/swap/canister/canister.rs`:

```rust
async fn refresh_buyer_tokens(arg: RefreshBuyerTokensRequest) -> RefreshBuyerTokensResponse {
    let caller = caller_principal_id();
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller
    } else {
        let requested = PrincipalId::from_str(&arg.buyer).unwrap();
        assert_eq!(caller, requested, "Caller must match the specified buyer");
        requested
    };
    ...
}
```

If third-party relayer notification is intentionally desired, the confirmation text must be a per-buyer secret (e.g., a buyer-signed nonce), not a single public string shared across all participants.

## Proof of Concept

**Setup:** SNS swap is `Open`. Confirmation text is `"I agree to the terms"` (read from `get_init`). Alice has transferred 10 ICP to her swap subaccount (`principal_to_subaccount(alice)` on the swap canister) but has not yet called `refresh_buyer_tokens`.

**Attack (reproducible as a state-machine integration test):**

```rust
// Attacker calls from their own identity with Alice's principal in the buyer field
env.execute_ingress_as(
    attacker_principal,
    swap_canister_id,
    "refresh_buyer_tokens",
    Encode!(&RefreshBuyerTokensRequest {
        buyer: alice_principal.to_string(),
        confirmation_text: Some("I agree to the terms".to_string()),
    }).unwrap(),
).unwrap();
```

**Expected result:**
- `refresh_buyer_token_e8s` reads Alice's subaccount balance (10 ICP).
- Alice's entry is created in `self.buyers` with `amount_icp_e8s = 10_0000_0000`.
- Alice never called `refresh_buyer_tokens` herself and never explicitly accepted the confirmation text.
- If the swap subsequently commits, Alice's 10 ICP is swept to the SNS treasury and she receives SNS tokens with no recourse until after finalization.

The existing test helper `participate_in_swap` in `rs/sns/test_utils/src/state_test_helpers.rs` lines 291–309 already demonstrates this pattern: it calls `execute_ingress` (anonymous caller) with an explicit `buyer` field set to the participant's principal, confirming the endpoint accepts cross-principal calls without error.