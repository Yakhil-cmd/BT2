Audit Report

## Title
Missing Caller Validation in `refresh_buyer_tokens` Enables Forced Participation and Confirmation-Text Consent Bypass - (File: rs/sns/swap/canister/canister.rs)

## Summary
The SNS Swap canister's `refresh_buyer_tokens` update method accepts an arbitrary `buyer` principal in its request payload without verifying that the caller matches the specified buyer. Any unprivileged ingress sender can call this method with a victim's principal as `buyer`, supplying the publicly-known `confirmation_text` on the victim's behalf, registering the victim's ICP as committed swap participation and permanently blocking the victim's ability to recover their ICP via `error_refund_icp` until after `sweep_icp` runs during finalization.

## Finding Description

In `rs/sns/swap/canister/canister.rs` L127–143, the `refresh_buyer_tokens` update method resolves the buyer principal from the request payload with no caller check:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()  // no check that caller == buyer
};
```

The `validate_confirmation_text` function in `rs/sns/swap/src/swap.rs` L363–384 only performs a string equality check against the SNS-configured text — it does not verify the identity of who is supplying it. The confirmation text is publicly readable via the `get_init` query endpoint.

The downstream `refresh_buyer_token_e8s` in `rs/sns/swap/src/swap.rs` L1134–1311 then:
1. Reads the ICP ledger balance of the victim's subaccount on the swap canister.
2. Validates the attacker-supplied `confirmation_text` against the SNS-configured required text.
3. Inserts the victim into `self.buyers` and calls `update_total_participation_amounts`.

Once a victim is registered in `self.buyers`, `error_refund_icp` in `rs/sns/swap/src/swap.rs` L1925–2032 explicitly blocks refunds for that principal until `sweep_icp` has completed (L1950–1959: returns a precondition error if `transfer_success_timestamp_seconds == 0`). This is confirmed by the test `test_error_refund_single_user` which asserts the error contains `"ABORTED or COMMITTED"` and `"escrow"`. By contrast, a victim who never had `refresh_buyer_tokens` called on their behalf can freely recover their ICP via `error_refund_icp` after the swap closes, as demonstrated in `test_error_refund_after_close` (user2 who never called `refresh_buyer_tokens` successfully refunds after the swap commits).

## Impact Explanation

This matches the allowed impact: **Significant SNS security impact with concrete user or protocol harm** (High, $2,000–$10,000).

Concrete harms:
- **Forced participation**: A victim who transferred ICP to their swap subaccount to evaluate participation, but had not yet decided to confirm, can be forcibly registered as a participant. Their ICP is locked in escrow and cannot be recovered via `error_refund_icp` until after `sweep_icp` runs during finalization.
- **Confirmation-text consent bypass**: The confirmation text is the SNS's only on-chain consent signal. An attacker can supply it on behalf of any victim, circumventing the consent gate entirely.
- **Swap lifecycle manipulation**: An attacker can register many victims simultaneously, pushing `direct_participation_icp_e8s` over the committed threshold and altering the swap's lifecycle outcome (triggering early commitment).
- **Irreversible outcome**: If the swap commits, the victim's ICP is swept to SNS governance and they receive SNS tokens — an outcome they explicitly had not consented to.

## Likelihood Explanation

Medium. The attack requires the victim to have already transferred ICP to their swap subaccount but not yet called `refresh_buyer_tokens`. This window is a normal part of the payment flow (transfer ICP → call `refresh_buyer_tokens`). The confirmation text is public (set in SNS init args, readable via `get_init`). No privileged access is required; any ingress sender can execute this. The attack is repeatable across any number of victims simultaneously.

## Recommendation

Add a caller-identity check when `buyer` is explicitly specified in `rs/sns/swap/canister/canister.rs`:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    let specified = PrincipalId::from_str(&arg.buyer).unwrap();
    if specified != caller_principal_id() {
        panic!("Caller must match the specified buyer");
    }
    specified
};
```

Alternatively, remove the `buyer` field entirely and always derive the buyer from `caller_principal_id()`, consistent with how other sensitive swap methods (e.g., `new_sale_ticket`, `notify_payment_failure`) operate.

## Proof of Concept

1. Victim transfers `min_participant_icp_e8s` ICP to the swap canister's subaccount for their principal (the normal first step of participation).
2. Victim has not yet called `refresh_buyer_tokens` (still deciding whether to confirm the swap terms).
3. Attacker reads the SNS's required `confirmation_text` from the public `get_init` query endpoint.
4. Attacker submits an ingress update call to the swap canister:
   ```
   refresh_buyer_tokens({
     buyer: "<victim_principal_text>",
     confirmation_text: Some("<required_confirmation_text>")
   })
   ```
5. The swap canister reads the victim's ICP balance (≥ `min_participant_icp_e8s`), validates the attacker-supplied confirmation text, and inserts the victim into `self.buyers` — all without the victim's explicit consent.
6. The victim's ICP is now locked in escrow. `error_refund_icp` returns a precondition error (`"ICP cannot be refunded as principal X has Y ICP (e8s) in escrow"`) until `sweep_icp` runs during finalization.
7. If the swap commits, the victim's ICP is swept to SNS governance and they receive SNS tokens against their will. If the swap aborts, they must wait for `sweep_icp` to run before recovering their ICP.

A deterministic integration test can be written using PocketIC: set up a swap in OPEN state with a `confirmation_text`, have a victim transfer ICP to their subaccount without calling `refresh_buyer_tokens`, then have a separate attacker principal call `refresh_buyer_tokens` with `buyer = victim_principal` and the correct `confirmation_text`, and assert that the victim appears in `self.buyers` and that `error_refund_icp` returns the escrow precondition error.