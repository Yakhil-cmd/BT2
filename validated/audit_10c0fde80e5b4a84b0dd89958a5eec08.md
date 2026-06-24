Audit Report

## Title
Arbitrary `buyer` Principal in `refresh_buyer_tokens` Bypasses Confirmation-Text Consent Gate — (`rs/sns/swap/canister/canister.rs`)

## Summary
The `refresh_buyer_tokens` update endpoint in the SNS Swap canister accepts a caller-supplied `buyer` string and resolves it to an arbitrary `PrincipalId` with no check that the caller equals the resolved buyer. Because the confirmation text is a publicly readable value set at SNS initialization, any unprivileged caller can invoke `refresh_buyer_tokens` with a victim's principal and the correct public confirmation text, registering the victim's already-deposited ICP as accepted swap participation without the victim's explicit consent.

## Finding Description
In `rs/sns/swap/canister/canister.rs` lines 130–134, the buyer principal is resolved as:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()  // no caller == buyer check
};
``` [1](#0-0) 

This `p` is passed directly to `refresh_buyer_token_e8s`, which:
1. Validates the confirmation text against the SNS-configured value — a public string readable from swap state.
2. Reads the ICP balance of `Account { owner: swap_canister, subaccount: principal_to_subaccount(&buyer) }`.
3. Credits that balance as the buyer's accepted participation. [2](#0-1) 

There is no guard anywhere in the call chain that enforces `caller == buyer`. The `RefreshBuyerTokensRequest.buyer` proto field is documented as "If not specified, the caller is used," implying an optional convenience field, but the canister imposes no restriction on who may supply it. [3](#0-2) 

The confirmation text is the sole consent gate for swap participation. Allowing any caller to supply it on behalf of an arbitrary principal completely nullifies this mechanism.

## Impact Explanation
A victim (Alice) who has transferred ICP to the swap canister's per-principal subaccount — even while still reviewing the confirmation text — can have her participation forcibly registered by an attacker. During the swap's `Open` lifecycle, Alice cannot withdraw those funds; `error_refund_icp` is only available after the swap closes. If the swap commits, Alice receives SNS tokens she never consented to receive in exchange for her ICP. This constitutes a **significant SNS security impact with concrete user harm**: the confirmation-text consent mechanism is entirely bypassed, and a victim's funds are locked and committed without their agreement. This matches the **High ($2,000–$10,000)** impact tier: "Significant SNS security impact with concrete user or protocol harm."

## Likelihood Explanation
- The `buyer` field is a plain string in a publicly callable update endpoint — no special privilege is required.
- The confirmation text is set at SNS initialization and is publicly readable from the swap's state.
- Any ICP deposited to the swap canister's subaccount (even accidentally, or while a user is still reviewing terms) is immediately exploitable.
- The attack requires a single ingress message and zero on-chain cost beyond the standard IC ingress fee.
- The attack is repeatable for any victim who has deposited ICP but not yet called `refresh_buyer_tokens`.

## Recommendation
Enforce that the resolved buyer principal equals the ingress caller:

```rust
async fn refresh_buyer_tokens(arg: RefreshBuyerTokensRequest) -> RefreshBuyerTokensResponse {
    let caller = caller_principal_id();
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller
    } else {
        let requested = PrincipalId::from_str(&arg.buyer).unwrap();
        assert_eq!(caller, requested, "caller must match buyer");
        requested
    };
    ...
}
```

Alternatively, remove the `buyer` override field entirely and always use `caller_principal_id()`. The only legitimate use case for the override (third-party notification that a user has deposited ICP) does not require bypassing the caller check — the ICP balance is read from the ledger, not from the caller — but the confirmation text must be supplied by the actual participant. [4](#0-3) 

## Proof of Concept
1. Alice calls `icrc1_transfer` on the ICP ledger, sending 10 ICP to `Account { owner: swap_canister_id, subaccount: principal_to_subaccount(Alice) }`.
2. Alice has not yet called `refresh_buyer_tokens` because she is still reviewing the confirmation text.
3. Attacker reads the swap's public `confirmation_text` from the swap's publicly accessible init/state.
4. Attacker submits an ingress message to the swap canister:
   ```
   refresh_buyer_tokens({
     buyer: "Alice's principal string",
     confirmation_text: Some("<public confirmation text>")
   })
   ```
5. The swap canister resolves `p = Alice`, reads Alice's subaccount balance (10 ICP), validates the confirmation text (passes, because the attacker supplied the correct public string), and credits Alice's participation.
6. Alice's 10 ICP is now locked as accepted swap participation. Alice never explicitly agreed to the confirmation text.

A deterministic integration test using PocketIC can reproduce this by: (a) opening a swap with a non-empty `confirmation_text`, (b) transferring ICP to Alice's subaccount without Alice calling `refresh_buyer_tokens`, (c) calling `refresh_buyer_tokens` from a different principal with `buyer = Alice` and the correct confirmation text, and (d) asserting that Alice's participation is registered in `swap().buyers`. [5](#0-4)

### Citations

**File:** rs/sns/swap/canister/canister.rs (L127-143)
```rust
#[update]
async fn refresh_buyer_tokens(arg: RefreshBuyerTokensRequest) -> RefreshBuyerTokensResponse {
    log!(INFO, "refresh_buyer_tokens");
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller_principal_id()
    } else {
        PrincipalId::from_str(&arg.buyer).unwrap()
    };
    let icp_ledger = create_real_icp_ledger(swap().init_or_panic().icp_ledger_or_panic());
    match swap_mut()
        .refresh_buyer_token_e8s(p, arg.confirmation_text, this_canister_id(), &icp_ledger)
        .await
    {
        Ok(r) => r,
        Err(msg) => panic!("{}", msg),
    }
}
```

**File:** rs/sns/swap/src/swap.rs (L1134-1163)
```rust
    pub async fn refresh_buyer_token_e8s(
        &mut self,
        buyer: PrincipalId,
        confirmation_text: Option<String>,
        this_canister: CanisterId,
        icp_ledger: &dyn ICRC1Ledger,
    ) -> Result<RefreshBuyerTokensResponse, String> {
        use swap_participation::*;

        // These two checks need to be repeated after awaiting the response from the ICP ledger.
        self.validate_lifecycle_is_open()
            .map_err(context_before_awaiting_icp_ledger_response)?;
        self.validate_possibility_of_direct_participation()
            .map_err(context_before_awaiting_icp_ledger_response)?;

        // User input validation doesn't expire after await, so this check doesn't need repetition.
        self.validate_confirmation_text(confirmation_text)?;

        // Look for the token balance of the specified principal's subaccount on 'this' canister.
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

**File:** rs/sns/swap/src/gen/ic_sns_swap.pb.v1.rs (L1117-1126)
```rust
pub struct RefreshBuyerTokensRequest {
    /// If not specified, the caller is used.
    #[prost(string, tag = "1")]
    pub buyer: ::prost::alloc::string::String,
    /// To accept the swap participation confirmation, a participant should send
    /// the confirmation text via refresh_buyer_tokens, matching the text set
    /// during SNS initialization.
    #[prost(string, optional, tag = "2")]
    pub confirmation_text: ::core::option::Option<::prost::alloc::string::String>,
}
```
