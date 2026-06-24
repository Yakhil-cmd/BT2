Audit Report

## Title
Unauthorized SNS Swap Participation Registration via Arbitrary `buyer` Parameter Bypasses Confirmation-Text Consent Mechanism - (File: `rs/sns/swap/canister/canister.rs`)

## Summary
The `refresh_buyer_tokens` update endpoint in the SNS Swap canister resolves the effective buyer principal from the request payload rather than from `msg_caller()`, with no check that the caller equals the supplied `buyer`. Because the `confirmation_text` is publicly readable via `get_init`, any unprivileged caller can register a victim's ICP participation — including submitting the confirmation text on the victim's behalf — bypassing the explicit consent mechanism the SNS operator configured.

## Finding Description
In `rs/sns/swap/canister/canister.rs` at lines 130–134, when `arg.buyer` is non-empty the handler resolves `p` directly from the payload string with no authorization check:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()  // no caller == buyer assertion
};
```

This `p` is passed directly to `refresh_buyer_token_e8s` along with `arg.confirmation_text`. Inside that function (`rs/sns/swap/src/swap.rs`, lines 1149–1163), `validate_confirmation_text` performs a pure text-equality check against the SNS's publicly readable init config — it is not bound to the caller's identity. The function then reads the ICP balance of the subaccount derived from the supplied `buyer` principal and records that principal as a committed participant.

The ticket system at lines 1250–1272 provides no protection: the guard is wrapped in `if let Some(ticket) = ...`, and the comment at line 1271 explicitly states "If there exists no ticket for the buyer, the payment flow will simply ignore the ticket." An attacker targeting a victim who has no open ticket (the common case before the victim calls `refresh_buyer_tokens` themselves) bypasses this check entirely.

The exploit path is:
1. Victim transfers ICP to their swap subaccount (normal first step of participation).
2. Attacker queries `get_init` (public query) to read `confirmation_text`.
3. Attacker calls `refresh_buyer_tokens` with `buyer = victim_principal` and the correct `confirmation_text`.
4. The canister resolves `p = victim_principal`, passes `validate_confirmation_text` (text matches), reads the victim's subaccount balance, and records the victim as a committed buyer.
5. On swap commit, the victim's ICP is swept to the SNS treasury and the victim receives SNS tokens they never explicitly agreed to purchase.

## Impact Explanation
This is a **High** severity finding. The `confirmation_text` mechanism is the sole explicit-consent gate for SNS swap participation. An unprivileged attacker can irrevocably commit a victim's ICP to a swap without the victim's consent at the time of the call. Once committed and the swap finalizes, the victim cannot reverse the exchange — they receive SNS tokens and their ICP is gone. This constitutes unauthorized access to and irreversible disposition of a victim's ledger assets, matching the allowed impact: *"Unauthorized access to neurons, governance assets, wallets, identities, ledgers, or canister-controlled funds."*

## Likelihood Explanation
The precondition — victim has transferred ICP to the swap subaccount — is the normal first step of the participation flow and is publicly observable on-chain. The attack window is the interval between the ICP transfer and the victim's own `refresh_buyer_tokens` call. The attacker needs only the victim's principal (publicly observable) and the `confirmation_text` (readable via a public query). No privileged access, key material, or threshold corruption is required. Any unprivileged ingress sender can execute this against any victim who has funded their subaccount.

## Recommendation
Enforce that when `confirmation_text` is supplied, the resolved buyer must equal the caller:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    let p = PrincipalId::from_str(&arg.buyer).unwrap();
    if arg.confirmation_text.is_some() && p != caller_principal_id() {
        panic!("confirmation_text can only be submitted by the buyer themselves");
    }
    p
};
```

Alternatively, remove the ability to specify an arbitrary `buyer` entirely and always use `caller_principal_id()`, relegating third-party notification to a separate endpoint that does not accept `confirmation_text`.

## Proof of Concept
Minimal deterministic integration test (PocketIC or state-machine test):

1. Deploy SNS swap canister with `confirmation_text = "I agree to the SNS token sale terms"` in init.
2. Fund Alice's swap subaccount with 100 ICP via the ICP ledger.
3. As the attacker (a different principal), call `refresh_buyer_tokens` with `buyer = alice_principal.to_text()` and `confirmation_text = Some("I agree to the SNS token sale terms")`.
4. Assert the call succeeds and `swap.buyers` contains Alice's principal with `amount_icp_e8s = 100_0000_0000`.
5. Finalize the swap; assert Alice's ICP is swept and she receives SNS tokens despite never having called `refresh_buyer_tokens` herself.