The code is confirmed. Let me also check the `validate_confirmation_text` function and the broader design intent around the notification pattern.

Audit Report

## Title
Third Party Can Bypass Confirmation Text Consent Gate and Commit Victim's ICP to SNS Swap - (File: rs/sns/swap/canister/canister.rs)

## Summary
The `refresh_buyer_tokens` endpoint accepts an arbitrary `buyer` principal without verifying it matches the ingress caller. Because the SNS `confirmation_text` is publicly readable and the code only checks that the supplied text matches the stored text — not that the caller is the buyer — any unprivileged third party can call `refresh_buyer_tokens` with `buyer = <victim>` and the public confirmation text, committing the victim's already-deposited ICP to the swap without the victim ever having consented.

## Finding Description
In `rs/sns/swap/canister/canister.rs` (L130–134), the buyer principal is resolved from the request payload with no caller-identity check:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()  // no check: p == caller
};
``` [1](#0-0) 

The resolved `p` is passed directly to `refresh_buyer_token_e8s`, which calls `validate_confirmation_text` — a pure string-equality check against the SNS-configured text stored in `init.confirmation_text`:

```rust
(Some(expected_text), Some(text)) => {
    if &text != expected_text { Err(...) } else { Ok(()) }
}
``` [2](#0-1) 

There is no check that the caller is the buyer at any point in `refresh_buyer_token_e8s`. [3](#0-2) 

The `confirmation_text` is stored in the public `Init` struct and is readable by anyone via `get_sale_parameters` or `get_state`. The proto documentation for `RefreshBuyerTokensRequest` states "a **participant** should send the confirmation text" — implying the buyer themselves must supply it — but the code imposes no such constraint. [4](#0-3) 

The integration test in `rs/tests/nns/sns/lib/src/sns_deployment.rs` confirms that a third-party agent calling `refresh_buyer_tokens` with `buyer = wealthy_user` and `confirmation_text = None` succeeds after the transfer, and this is treated as expected behavior. However, the test never exercises the case where a third party also supplies the `confirmation_text`, leaving the consent bypass untested and unguarded. [5](#0-4) 

**Exploit flow:**
1. SNS swap is `Open` with `confirmation_text = "I accept the terms"` (readable via `get_state`).
2. Victim `V` transfers 100 ICP to `principal_to_subaccount(V)` on the ICP ledger, intending to review the terms before calling `refresh_buyer_tokens`.
3. Attacker `A` (any non-anonymous principal) calls:
   ```
   refresh_buyer_tokens({ buyer: "<V_principal>", confirmation_text: opt "I accept the terms" })
   ```
4. `validate_confirmation_text` passes (text matches). The 100 ICP balance is read for `V`'s subaccount and recorded as `V`'s committed participation.
5. On `finalize_swap`, `V`'s ICP is swept to the SNS treasury and `V` receives SNS tokens — without `V` ever having called `refresh_buyer_tokens`.

## Impact Explanation
This is a **High** severity finding matching the allowed impact: *"Significant SNS security impact with concrete user or protocol harm."* The confirmation text is the only explicit per-user consent gate in the SNS swap participation flow. Bypassing it allows an attacker to force a victim into a binding financial commitment (ICP → SNS tokens) without consent. If the SNS token price at swap close is below the ICP price paid, the victim suffers a direct, irrecoverable financial loss, since `finalize_swap` sweeps the ICP out of the subaccount. The attack is not hypothetical — it is directly triggerable against any victim who has deposited ICP but not yet called `refresh_buyer_tokens`.

## Likelihood Explanation
The attack requires no privileged access, no key material, and no on-chain preconditions beyond the victim having deposited ICP into their swap subaccount. The `confirmation_text` is publicly readable from swap state. The `buyer` field is a plain string in the Candid interface. The victim's swap subaccount is deterministically derived via `principal_to_subaccount`, so the attacker can verify the victim's balance before attacking. The attack is repeatable for every victim who deposits ICP before calling `refresh_buyer_tokens`.

## Recommendation
Add a caller-identity check in `refresh_buyer_tokens` (or inside `refresh_buyer_token_e8s`) that rejects calls where a non-empty `buyer` field does not match the ingress caller **when a `confirmation_text` is required**. The minimal fix is:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    let requested = PrincipalId::from_str(&arg.buyer).unwrap();
    // If a confirmation_text is required, only the buyer themselves may supply it.
    if arg.confirmation_text.is_some() && requested != caller_principal_id() {
        panic!("buyer field must match the caller when confirmation_text is provided");
    }
    requested
};
```

Alternatively, enforce unconditionally that a non-empty `buyer` must equal the caller, preserving the existing third-party notification use-case only when no confirmation text is configured for the swap.

## Proof of Concept
**Local PocketIC / StateMachine test plan:**
1. Initialize a swap with `confirmation_text = Some("I accept the terms")` and `lifecycle = Open`.
2. Simulate victim `V` transferring 10 ICP to `principal_to_subaccount(V)` on the mock ICP ledger.
3. As attacker `A` (a different principal), call `refresh_buyer_tokens` with `buyer = V.to_string()` and `confirmation_text = Some("I accept the terms")`.
4. Assert the call returns `Ok` and that `swap.buyers` now contains an entry for `V` with `amount_icp_e8s > 0`.
5. Assert that `V` never called `refresh_buyer_tokens` themselves (verified by the test setup).

This directly mirrors the existing `test_swap_participation_confirmation` test structure in `rs/sns/swap/tests/swap.rs` (L5637–5700) and can be reproduced with a two-principal mock without any mainnet interaction. [6](#0-5)

### Citations

**File:** rs/sns/swap/canister/canister.rs (L130-134)
```rust
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller_principal_id()
    } else {
        PrincipalId::from_str(&arg.buyer).unwrap()
    };
```

**File:** rs/sns/swap/src/swap.rs (L371-374)
```rust
                (Some(expected_text), Some(text)) => {
                    if &text != expected_text {
                        Err("The value of `confirmation_text` does not match the value provided in SNS init payload.".to_string())
                    } else {
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

**File:** rs/tests/nns/sns/lib/src/sns_deployment.rs (L919-948)
```rust
    // Use the default identity to call refresh_buyer_tokens for the wealthy user
    let res_4 = {
        let request = sns_request_provider
            .refresh_buyer_tokens(Some(wealthy_user_identity.principal_id), None);
        block_on(default_sns_agent.call_and_parse(&request))
            .result()
            .unwrap()
    };
    info!(
        log,
        "Third update call to `sns_sale.refresh_buyer_tokens` returned {res_4:?} (elapsed {:?})",
        start_time.elapsed()
    );
    // Use the wealthy user's identity to call refresh_buyer_tokens for "self"
    let res_5 = {
        let request = sns_request_provider.refresh_buyer_tokens(None, None);
        block_on(wealthy_sns_agent.call_and_parse(&request))
            .result()
            .unwrap()
    };
    info!(
        log,
        "Fourth update call to `sns_sale.refresh_buyer_tokens` returned {res_5:?} (elapsed {:?})",
        start_time.elapsed()
    );
    assert_eq!(
        res_4, res_5,
        "sns_sale.refresh_buyer_tokens(Some({:?}), None) = {res_4:?}, but sns_sale.refresh_buyer_tokens(None, None) = {res_5:?}",
        wealthy_user_identity.principal_id
    );
```

**File:** rs/sns/swap/tests/swap.rs (L5637-5700)
```rust
/// Test that the `refresh_buyer_token_e8s` function handles confirmations correctly.
#[test]
fn test_swap_participation_confirmation() {
    let confirmation_text = "Please confirm that 2+2=4".to_string();
    let another_text = "Please confirm that 2+2=5".to_string();
    let user = PrincipalId::new_user_test_id(1);
    let amount = 101 * E8;

    let buy_token = |swap: &mut Swap, confirmation_text: Option<String>| {
        swap.refresh_buyer_token_e8s(
            user,
            confirmation_text,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&user)),
                },
                Ok(Tokens::from_e8s(amount)),
            )]),
        )
        .now_or_never()
        .unwrap()
    };

    // A. SNS specifies confirmation text & client sends confirmation text
    {
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Open)
            .with_confirmation_text(confirmation_text.clone())
            .build();
        // A.1. The texts match
        assert_is_ok!(buy_token(&mut swap, Some(confirmation_text.clone())));
        // A.2. The texts do not match
        assert_is_err!(buy_token(&mut swap, Some(another_text)));
    }

    // B. SNS specifies confirmation text & client does not send a confirmation text
    {
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Open)
            .with_confirmation_text(confirmation_text.clone())
            .build();
        assert_is_err!(buy_token(&mut swap, None));
    }

    // C. SNS does not specify confirmation text & client sends a confirmation text
    {
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Open)
            .without_confirmation_text()
            .build();
        assert_is_err!(buy_token(&mut swap, Some(confirmation_text)));
    }

    // D. SNS does not specify confirmation text & client does not send a confirmation text
    {
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Open)
            .without_confirmation_text()
            .build();
        assert_is_ok!(buy_token(&mut swap, None));
    }
}
```
