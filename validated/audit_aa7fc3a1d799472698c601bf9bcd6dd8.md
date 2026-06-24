Audit Report

## Title
Unauthenticated `buyer` Field in `refresh_buyer_tokens` Allows Forced Swap Participation and Confirmation-Text Consent Bypass - (File: `rs/sns/swap/canister/canister.rs`)

## Summary
The `refresh_buyer_tokens` endpoint in the SNS Swap canister accepts an arbitrary `buyer` principal without verifying the caller matches that principal. Any unprivileged ingress sender can trigger step 2 of the two-step participation flow on behalf of any victim who has already completed step 1 (ICP transfer), forcing their participation and supplying the confirmation text on their behalf, thereby bypassing the SNS-configured consent mechanism.

## Finding Description
In `rs/sns/swap/canister/canister.rs` lines 128–143, the handler resolves the buyer from the request field with no caller-identity check:

```rust
let p: PrincipalId = if arg.buyer.is_empty() {
    caller_principal_id()
} else {
    PrincipalId::from_str(&arg.buyer).unwrap()  // no check that caller == p
};
``` [1](#0-0) 

The `RefreshBuyerTokensRequest` struct exposes `buyer` as a plain string and `confirmation_text` as an optional string, both fully attacker-controlled: [2](#0-1) 

Inside `refresh_buyer_token_e8s`, the supplied `buyer` principal is used directly to derive the subaccount and credit participation — no caller check exists anywhere in the call chain: [3](#0-2) 

`validate_confirmation_text` is called with the attacker-supplied `confirmation_text` value. Since the confirmation text is set at SNS initialization and is publicly queryable, any attacker can supply the correct text: [4](#0-3) 

A grep for any `caller == buyer` or equivalent authorization check across all swap Rust sources returns no matches, confirming no guard exists.

The test helper in `rs/sns/test_utils/src/state_test_helpers.rs` further confirms the design: it calls `refresh_buyer_tokens` with `buyer: participant_principal_id.to_string()` from a different caller (the state machine's default sender), demonstrating the endpoint is reachable by third parties: [5](#0-4) 

## Impact Explanation
This maps to **High ($2,000–$10,000)**: "Significant SNS security impact with concrete user or protocol harm."

1. **Forced participation**: A victim who has sent ICP to the swap subaccount but not yet called `refresh_buyer_tokens` (a normal intermediate state) can have their participation committed by any attacker. The victim's ICP is locked for the duration of the swap (potentially days) and cannot be reclaimed until the swap closes via `error_refund_icp`.
2. **Confirmation-text consent bypass**: The `confirmation_text` field is the only explicit consent signal in the SNS participation flow — it is intended to require the participant to acknowledge a legal disclaimer or risk warning. Because any caller can supply this text on behalf of any buyer, the consent mechanism is completely undermined for every SNS swap that uses it.

The ICP is not permanently stolen, which limits severity below Critical, but the temporary fund lockup and complete nullification of the consent mechanism constitute concrete, demonstrable harm to SNS participants.

## Likelihood Explanation
The attack window exists for every user in the normal intermediate state between step 1 (ICP transfer) and step 2 (`refresh_buyer_tokens` call). The attacker requires only: the victim's principal (public on-chain), the confirmation text (publicly queryable from swap init), and the ability to submit an ingress message before the victim. No privileged access, key material, or majority corruption is required. The attack is repeatable against any victim in any open SNS swap.

## Recommendation
Enforce `caller == buyer` when a non-empty `buyer` field is supplied, mirroring the pattern used in `rs/nns/cmc/src/main.rs` for `notify_create_canister`:

```rust
async fn refresh_buyer_tokens(arg: RefreshBuyerTokensRequest) -> RefreshBuyerTokensResponse {
    let caller = caller_principal_id();
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller
    } else {
        let requested = PrincipalId::from_str(&arg.buyer).unwrap();
        if requested != caller {
            panic!("Caller {} is not authorized to refresh tokens on behalf of {}", caller, requested);
        }
        requested
    };
    // ...
}
``` [6](#0-5) 

## Proof of Concept
1. Deploy an SNS swap with `confirmation_text = "I accept the risk"`.
2. Victim (`principal V`) sends 10 ICP to `swap_canister[subaccount = principal_to_subaccount(V)]` but does not yet call `refresh_buyer_tokens`.
3. Attacker (`principal A`, any unprivileged user) queries the swap init to obtain the confirmation text.
4. Attacker submits ingress: `refresh_buyer_tokens({ buyer: "<V's principal>", confirmation_text: Some("I accept the risk") })`.
5. The swap canister resolves `p = V`, checks the balance at `swap_canister[subaccount=hash(V)]`, finds 10 ICP, validates the attacker-supplied confirmation text, and records V as a committed participant.
6. V's ICP is now locked in the swap. V never explicitly agreed to the confirmation text. V cannot reclaim ICP until the swap closes.

This is directly reproducible using the existing `participate_in_swap` test helper pattern in `rs/sns/test_utils/src/state_test_helpers.rs` by calling `execute_ingress` with a sender different from `participant_principal_id`. [7](#0-6)

### Citations

**File:** rs/sns/swap/canister/canister.rs (L130-134)
```rust
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller_principal_id()
    } else {
        PrincipalId::from_str(&arg.buyer).unwrap()
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

**File:** rs/sns/swap/src/swap.rs (L1149-1150)
```rust
        // User input validation doesn't expire after await, so this check doesn't need repetition.
        self.validate_confirmation_text(confirmation_text)?;
```

**File:** rs/sns/swap/src/swap.rs (L1152-1163)
```rust
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

**File:** rs/sns/test_utils/src/state_test_helpers.rs (L276-310)
```rust
pub fn participate_in_swap(
    state_machine: &StateMachine,
    swap_canister_id: CanisterId,
    participant_principal_id: PrincipalId,
    amount: ExplosiveTokens,
) -> RefreshBuyerTokensResponse {
    // First, transfer ICP to swap. Needs to go into a special subaccount...
    send_participation_funds(
        state_machine,
        swap_canister_id,
        participant_principal_id,
        amount,
    );

    // ... then, swap must be notified about that transfer.
    let response = state_machine
        .execute_ingress(
            swap_canister_id,
            "refresh_buyer_tokens",
            Encode!(&RefreshBuyerTokensRequest {
                buyer: participant_principal_id.to_string(),
                confirmation_text: None,
            })
            .unwrap(),
        )
        .unwrap();
    let response = match response {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("refresh_buyer_tokens was rejected by the swap canister: {reject:#?}")
        }
    };

    Decode!(&response, RefreshBuyerTokensResponse).unwrap()
}
```

**File:** rs/nns/cmc/src/main.rs (L1438-1474)
```rust
fn authorize_caller_to_call_notify_create_canister_on_behalf_of_creator(
    caller: PrincipalId,
    creator: PrincipalId,
) -> Result<(), NotifyError> {
    if caller == creator {
        return Ok(());
    }

    // This is a hack to enable testing (related features) of nns-dapp. In
    // tests, the nns-dapp backend canister happens to use ID of the production
    // ICP ledger archive 1 canister. Ideally, the test nns-dapp backend
    // canister would have the same ID as the production nns-dapp backend
    // canister. This difference should probably be considered a bug. This hack
    // can be removed after that bug is fixed.
    const TEST_NNS_DAPP_BACKEND_CANISTER_ID: CanisterId = ICP_LEDGER_ARCHIVE_1_CANISTER_ID;
    lazy_static! {
        static ref ALLOWED_CALLERS: [PrincipalId; 2] = [
            PrincipalId::from(*NNS_DAPP_BACKEND_CANISTER_ID),
            PrincipalId::from(TEST_NNS_DAPP_BACKEND_CANISTER_ID),
        ];
    }

    if ALLOWED_CALLERS.contains(&caller) {
        return Ok(());
    }

    // Other is used, because adding a Unauthorized variant to NotifyError would
    // confuse old clients.
    let err = NotifyError::Other {
        error_code: NotifyErrorCode::Unauthorized as u64,
        error_message: format!(
            "{caller} is not authorized to call notify_create_canister on behalf \
             of {creator}. (Do not retry, because the same result will occur.)",
        ),
    };

    Err(err)
```
