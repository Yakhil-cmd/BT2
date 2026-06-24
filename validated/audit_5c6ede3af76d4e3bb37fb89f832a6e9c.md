The code confirms all the key claims. Let me verify the `validate_confirmation_text` implementation and whether there's any caller check anywhere in the call path.

Audit Report

## Title
Unprivileged Caller Can Force Victim's ICP Into SNS Swap and Bypass Confirmation-Text Consent Gate — (`rs/sns/swap/canister/canister.rs`)

## Summary
The `refresh_buyer_tokens` update endpoint on the SNS Swap canister accepts an arbitrary `buyer` principal in its request payload and performs no check that the caller equals that buyer. Any unprivileged ingress sender can therefore call the endpoint on behalf of any other user, committing that user's ICP to the swap and satisfying the swap's `confirmation_text` consent gate on their behalf — even though the victim never explicitly agreed. The confirmation text is publicly readable from `get_init`, making the gate trivially bypassable.

## Finding Description
In `rs/sns/swap/canister/canister.rs` lines 130–134, the effective buyer principal is resolved as:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()
};
```

When `arg.buyer` is non-empty, `p` is set to the attacker-supplied value with no check that `caller_principal_id() == p`. A grep across the entire `rs/sns/swap/` tree confirms there is no `caller == buyer` guard anywhere in the call path.

`p` is then passed directly to `refresh_buyer_token_e8s` (`swap.rs` lines 1134–1163). The only caller-supplied gate inside that function is `validate_confirmation_text` (`swap.rs` lines 363–384), which performs a pure string comparison against the value stored in the public `Init` state:

```rust
(Some(expected_text), Some(text)) => {
    if &text != expected_text { Err(...) } else { Ok(()) }
}
```

Because the confirmation text is stored in `Init` and exposed via the public `get_init` endpoint, any attacker can read it and supply it verbatim. After passing that check, the function reads the ICP ledger balance of the victim's subaccount (`swap.rs` line 1156), registers it as the victim's participation (`swap.rs` lines 1285–1288), and deletes the victim's open ticket (`swap.rs` line 1270) — all without any action by the victim.

## Impact Explanation
This is a **High** severity finding. The attack allows an unprivileged third party to:
1. **Bypass the confirmation-text consent gate** — SNS projects use `confirmation_text` as an explicit legal/regulatory consent mechanism. Because the text is public and no caller identity check is performed, the gate is entirely ineffective against a motivated attacker.
2. **Force premature participation** — A user who has transferred ICP to their swap subaccount but has not yet decided to participate can be forced into the swap, locking their ICP until the swap concludes (committed or aborted).
3. **Destroy the victim's open ticket** — The victim's ticket is silently deleted, breaking the payment-flow state machine for that user.

This matches the allowed High impact: *"Significant SNS security impact with concrete user or protocol harm"* and *"Unauthorized access to canister-controlled funds where exploitation requires meaningful per-target work or other constraints."*

## Likelihood Explanation
The attack requires only: knowledge of the victim's principal (public on-chain), knowledge of the swap's `confirmation_text` (readable from the public `get_init` endpoint), and the victim having already transferred ICP to their swap subaccount (a normal first step in the payment flow). No privileged access, key material, or majority corruption is required. The attacker pays only the cycles cost of a single update call. The attack is repeatable against any victim in any open SNS swap that uses `confirmation_text`.

## Recommendation
Require that the effective buyer principal equals the caller when a `confirmation_text` is present, or unconditionally enforce `caller == buyer` at the canister boundary:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    let specified = PrincipalId::from_str(&arg.buyer).unwrap();
    if swap().init_or_panic().confirmation_text.is_some()
        && specified != caller_principal_id()
    {
        panic!("Caller must equal the buyer when a confirmation text is required");
    }
    specified
};
```

Alternatively, remove the ability to specify an arbitrary `buyer` entirely and always use `caller_principal_id()`.

## Proof of Concept
1. Deploy an SNS swap with `confirmation_text = "I confirm I have read the terms."`.
2. Victim transfers 10 ICP to `swap_canister[principal_to_subaccount(victim)]` on the ICP ledger (normal first step).
3. Victim has not yet called `refresh_buyer_tokens` — they are still deciding.
4. Attacker calls `get_init` on the swap canister to read the confirmation text.
5. Attacker sends an ingress update call to `refresh_buyer_tokens` with `buyer = victim_principal_text` and `confirmation_text = "I confirm I have read the terms."`.
6. The swap canister resolves `p = victim_principal`, reads the victim's 10 ICP balance, validates the (public) confirmation text as if the victim supplied it, commits 10 ICP as the victim's participation, and deletes the victim's open ticket.
7. The victim is now a registered swap participant who has "agreed" to the terms, with their ICP locked in the swap — without ever having called the endpoint themselves.

This can be reproduced as a unit test by adapting the existing `test_swap_participation_confirmation` test in `rs/sns/swap/tests/swap.rs` to call `refresh_buyer_token_e8s` with a `buyer` principal that differs from the simulated caller.