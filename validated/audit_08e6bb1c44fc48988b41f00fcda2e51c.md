Audit Report

## Title
Unprivileged Caller Can Force Another Principal Into SNS Swap Participation, Bypassing `confirmation_text` Consent — (`rs/sns/swap/canister/canister.rs`)

## Summary
`refresh_buyer_tokens` resolves the effective buyer from the request argument rather than the authenticated caller, with no authorization check that `buyer == caller`. Because `validate_confirmation_text` only compares the supplied string against the publicly readable SNS init value — not against the caller's identity — any unprivileged ingress sender can commit another principal's pre-funded ICP into the swap on their behalf, bypassing the `confirmation_text` consent mechanism entirely. If the swap reaches `COMMITTED`, the victim's ICP is swept to SNS governance and SNS tokens are minted to them irreversibly.

## Finding Description

**Root cause — canister entry point (`rs/sns/swap/canister/canister.rs`, L130–134):**

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()  // no caller == buyer check
};
```

`p` is passed directly to `refresh_buyer_token_e8s` along with the caller-supplied `confirmation_text`. The inner function has no caller parameter and performs no identity check.

**Consent check is content-only, not identity-bound (`rs/sns/swap/src/swap.rs`, L363–384):**

`validate_confirmation_text` compares the supplied string against `self.init_or_panic().confirmation_text`. The `confirmation_text` is stored in the public `Init` struct and is returned by the `get_init` query. Any caller who reads this public value can pass the check on behalf of any victim.

**Funds committed without victim's action (`rs/sns/swap/src/swap.rs`, L1154–1163, L1285–1288):**

The function reads the balance of `subaccount(swap_canister, buyer)` on the ICP ledger and records a `BuyerState` for `buyer` with the observed balance. The victim's ICP is now in escrow.

**Refund is blocked while swap is OPEN (`rs/sns/swap/src/swap.rs`, L1932–1959):**

`error_refund_icp` is only callable when the swap is `ABORTED` or `COMMITTED`. While the swap is `OPEN` and the victim has a `BuyerState` with `transfer_success_timestamp_seconds == 0`, the refund path returns a precondition error: "ICP cannot be refunded as principal X has Y ICP (e8s) in escrow." The victim cannot exit the position until the swap closes.

**Existing checks are insufficient:**
- `validate_lifecycle_is_open` — checks swap state, not caller identity.
- `validate_possibility_of_direct_participation` — checks ICP target, not caller identity.
- `validate_confirmation_text` — checks string content against a public value, not caller identity.
- No check anywhere in the call path verifies `caller == buyer`.

## Impact Explanation

When the swap reaches `COMMITTED` and `sweep_icp` runs, the victim's ICP is transferred to SNS governance and SNS tokens are minted to the victim. This is irreversible. The victim's ICP is consumed and they receive an asset they never explicitly agreed to acquire. The `confirmation_text` mechanism — documented as "An optional text that swap participants should confirm before they may participate in the swap" — is rendered completely ineffective as a consent gate, since any third party can supply the public string. This constitutes a **significant SNS security impact with concrete user harm**: unauthorized commitment of a user's funds into a governance/financial instrument without their explicit consent, matching the High bounty impact class.

## Likelihood Explanation

- No privileged access is required; any ingress sender can call `refresh_buyer_tokens`.
- The victim precondition (ICP transferred to the swap subaccount) is observable on the public ICP ledger.
- The `confirmation_text` is publicly readable via `get_init`.
- Users commonly pre-fund their swap subaccounts before calling `refresh_buyer_tokens` themselves, creating a window for exploitation.
- The integration test at `rs/tests/nns/sns/lib/src/sns_deployment.rs` (L807–826, L919–926) explicitly demonstrates and validates the third-party calling pattern, confirming the attack path is reachable with no special setup.

Likelihood: **Medium-High**.

## Recommendation

Add a caller-identity check in `refresh_buyer_tokens` before accepting a third-party `buyer` value. If the specified `buyer` differs from the authenticated caller, the call should be rejected:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    let specified = PrincipalId::from_str(&arg.buyer).unwrap();
    if specified != caller_principal_id() {
        panic!("caller is not authorized to refresh tokens on behalf of {}", specified);
    }
    specified
};
```

If third-party notification is a desired feature (e.g., for bots), it should be separated from the `confirmation_text` consent path: allow third-party calls only when no `confirmation_text` is configured, or require the `confirmation_text` to be absent when `buyer != caller`.

## Proof of Concept

**Setup:** SNS swap is `Open`. Victim `V` transfers 10 ICP to `subaccount(swap_canister, V)` on the ICP ledger. SNS `confirmation_text` is `"I agree to the terms"` (readable via `get_init`).

**Attack (deterministic integration test using `StateMachine` or PocketIC):**

```rust
// Attacker calls refresh_buyer_tokens with buyer = V
state_machine.execute_ingress_as(
    attacker_principal,
    swap_canister_id,
    "refresh_buyer_tokens",
    Encode!(&RefreshBuyerTokensRequest {
        buyer: victim_principal.to_string(),
        confirmation_text: Some("I agree to the terms".to_string()),
    }).unwrap(),
).unwrap();
```

**Expected result:**
- `p` is set to `V` (attacker-controlled, no authorization check).
- `validate_confirmation_text` passes (attacker supplied the correct public string).
- `account_balance(subaccount(swap_canister, V))` returns 10 ICP.
- `BuyerState` for `V` is created with `amount_icp_e8s = 10 ICP`.
- `error_refund_icp` called by `V` while swap is `OPEN` returns precondition error "ICP cannot be refunded as principal V has 10 ICP (e8s) in escrow."
- When the swap finalizes as `COMMITTED`, `sweep_icp` transfers `V`'s ICP to SNS governance and SNS tokens are minted to `V` — without `V` ever calling `refresh_buyer_tokens` or explicitly agreeing to the terms.