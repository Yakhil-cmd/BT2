Audit Report

## Title
Unprivileged Caller Can Force Victim's ICP Into SNS Swap and Bypass Confirmation-Text Consent Gate — (`rs/sns/swap/canister/canister.rs`)

## Summary
The `refresh_buyer_tokens` endpoint resolves the effective buyer from the caller-supplied `arg.buyer` field without verifying that the caller equals the specified buyer. Because the swap's `confirmation_text` is publicly readable, any unprivileged attacker can call the endpoint on behalf of any victim who has already transferred ICP to their swap subaccount, committing that ICP to the swap, recording the victim as having consented to terms they never read, and destroying their open ticket.

## Finding Description
In `rs/sns/swap/canister/canister.rs` at L130–134, the effective buyer principal is resolved as:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()  // no caller == buyer check
};
``` [1](#0-0) 

The resolved `p` is passed directly to `refresh_buyer_token_e8s` at L137 without any assertion that `caller_principal_id() == p`. [2](#0-1) 

Inside `refresh_buyer_token_e8s`, the only caller-supplied gate is `validate_confirmation_text` at L1150, which checks that the supplied text matches the swap's stored text — it does not check caller identity. [3](#0-2) 

The confirmation text is stored in the swap's public `Init` state and is readable by anyone via `get_init`. It is not a secret. After passing that check, the function reads the ICP balance of the victim's subaccount at L1154–1163, registers it as the victim's participation, and at L1270 deletes the victim's open ticket — all keyed on the attacker-supplied `buyer` principal, not the caller. [4](#0-3) [5](#0-4) 

The proto definition at L844 explicitly documents the field as "If not specified, the caller is used," confirming the field is intentionally caller-overridable with no access control. [6](#0-5) 

## Impact Explanation
This is a **High** severity finding. An attacker can force any victim who has transferred ICP to their swap subaccount into the swap without their consent, locking their ICP until the swap concludes. The `confirmation_text` consent gate — intended to record explicit user agreement to legal or informational terms — is rendered entirely ineffective because the text is public and any caller can supply it on behalf of any buyer. The victim's open ticket is also silently destroyed, breaking the payment-flow state machine for that user. This constitutes a significant SNS security impact with concrete user harm: unauthorized commitment of user funds and a bypassed consent mechanism, matching the allowed High impact class of "Significant SNS or infrastructure security impact with concrete user or protocol harm."

## Likelihood Explanation
The attack requires no special privileges, no key material, and no majority corruption. The attacker needs only: (1) the victim's principal, which is public on-chain information; (2) the swap's `confirmation_text`, readable from the public `get_init` endpoint; and (3) the victim to have already transferred ICP to their swap subaccount, which is the normal first step of the payment flow. The attacker pays only the cycles cost of a single update call. The attack is repeatable against any eligible victim and requires no per-target technical work beyond knowing the victim's principal.

## Recommendation
Require that the effective buyer principal equals the caller when a `confirmation_text` is configured, or unconditionally enforce `caller == buyer`:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    let specified = PrincipalId::from_str(&arg.buyer).unwrap();
    if specified != caller_principal_id() {
        if swap().init_or_panic().confirmation_text.is_some() {
            panic!("Caller must be the buyer when a confirmation text is required");
        }
    }
    specified
};
```

Alternatively, remove the `buyer` override field entirely and always use `caller_principal_id()`, since any user can call the endpoint for themselves once they have transferred ICP.

## Proof of Concept
1. Deploy an SNS swap with `confirmation_text = "I confirm I have read the terms."`.
2. Victim transfers 10 ICP to `swap_canister[principal_to_subaccount(victim)]` on the ICP ledger (normal first step).
3. Victim has not yet called `refresh_buyer_tokens` — they are still deciding.
4. Attacker calls `get_init` on the swap canister to read the public `confirmation_text`.
5. Attacker sends an ingress update call to `refresh_buyer_tokens` with `buyer = victim_principal_text` and `confirmation_text = "I confirm I have read the terms."`.
6. The swap canister resolves `p = victim_principal` (L130–134), passes `validate_confirmation_text` (L1150) using the public text, reads the victim's 10 ICP balance from their subaccount (L1154–1163), commits 10 ICP as the victim's participation (L1285–1288), and deletes the victim's open ticket (L1270).
7. The victim is now a registered swap participant recorded as having agreed to the terms, with their ICP locked in the swap — without ever having called the endpoint themselves.

### Citations

**File:** rs/sns/swap/canister/canister.rs (L130-134)
```rust
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller_principal_id()
    } else {
        PrincipalId::from_str(&arg.buyer).unwrap()
    };
```

**File:** rs/sns/swap/canister/canister.rs (L136-138)
```rust
    match swap_mut()
        .refresh_buyer_token_e8s(p, arg.confirmation_text, this_canister_id(), &icp_ledger)
        .await
```

**File:** rs/sns/swap/src/swap.rs (L1149-1150)
```rust
        // User input validation doesn't expire after await, so this check doesn't need repetition.
        self.validate_confirmation_text(confirmation_text)?;
```

**File:** rs/sns/swap/src/swap.rs (L1153-1163)
```rust
        let e8s = {
            let account = Account {
                owner: this_canister.get().0,
                subaccount: Some(principal_to_subaccount(&buyer)),
            };
            icp_ledger
                .account_balance(account)
                .await
                .map_err(|x| x.to_string())?
                .get_e8s()
        };
```

**File:** rs/sns/swap/src/swap.rs (L1270-1270)
```rust
            memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow_mut().remove(&principal));
```

**File:** rs/sns/swap/proto/ic_sns_swap/pb/v1/swap.proto (L843-851)
```text
message RefreshBuyerTokensRequest {
  // If not specified, the caller is used.
  string buyer = 1;

  // To accept the swap participation confirmation, a participant should send
  // the confirmation text via refresh_buyer_tokens, matching the text set
  // during SNS initialization.
  optional string confirmation_text = 2;
}
```
