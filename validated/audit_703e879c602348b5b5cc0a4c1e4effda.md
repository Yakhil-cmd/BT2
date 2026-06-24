Audit Report

## Title
`nat_to_u64` Overflow in ICRC-21 `FieldsDisplayMessage` Consent Generation Blocks Hardware Wallet Signing for Large Token Amounts — (`packages/icrc-ledger-types/src/icrc21/responses.rs`)

## Summary
The `Value::TokenAmount` variant stores `amount` as a `u64`, and the private helper `nat_to_u64` returns a `GenericError` when a caller-supplied `Nat` exceeds `u64::MAX`. Any call to `icrc21_canister_call_consent_message` with `device_spec = FieldsDisplay` and an amount above `u64::MAX` (≈18.44 ckETH at 18 decimals) fails with an error instead of returning a consent message. Hardware wallets such as Ledger that exclusively use `FieldsDisplay` are therefore unable to display or sign large ckETH transfers or approvals.

## Finding Description
`Value::TokenAmount` declares `amount: u64`: [1](#0-0) 

`nat_to_u64` narrows an arbitrary-precision `Nat` to `u64` and propagates a `GenericError` on overflow: [2](#0-1) 

This helper is invoked in every `FieldsDisplayMessage` branch of `add_amount`, `add_fee`, `add_allowance`, and `add_existing_allowance`: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

`ConsentMessageBuilder::build()` propagates these errors via `?`: [7](#0-6) 

The `GenericDisplayMessage` branch is unaffected because it calls `convert_tokens_to_string_representation`, which converts to `f64` and never hits the `u64` ceiling: [8](#0-7) 

The `MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES = 500` guard does not prevent this: a Candid-encoded `Nat` of `u64::MAX + 1` occupies only ~10 bytes in LEB128, well within the limit: [9](#0-8) 

The public `#[update]` endpoint on the ICRC-1 ledger exposes this path to any unprivileged caller: [10](#0-9) 

The ICP ledger exposes the same endpoint and delegates to the same builder for ICRC-1/2 methods: [11](#0-10) 

## Impact Explanation
This qualifies as **High** under "Significant Chain Fusion, ck-token, ledger security impact with concrete user or protocol harm." Hardware wallets (e.g., Ledger) that implement ICRC-21 exclusively via `FieldsDisplay` cannot obtain a consent message for any ckETH transfer or approval exceeding ~18.44 ETH. Those users are effectively blocked from signing such transactions through their hardware wallet. The ICRC-21 consent message mechanism is itself a security control; its failure for a realistic and common amount range constitutes concrete harm to ckETH holders relying on hardware wallet security.

## Likelihood Explanation
The `icrc21_canister_call_consent_message` endpoint requires no special privileges. Any user can trigger the failure by submitting a `TransferArg` or `ApproveArgs` with `amount > u64::MAX` and `device_spec = Some(FieldsDisplay)`. For ckETH (18 decimals), the threshold is ~18.44 ETH — a realistic holding for institutional users, DeFi protocols, or any non-trivial holder. The Candid interface accepts `amount: nat` (arbitrary precision), so no upstream guard prevents large values from reaching the consent message builder.

## Recommendation
Replace the `u64` field in `Value::TokenAmount` with `Nat` (or `u128`) to accommodate the full ICRC-1 token amount range. Alternatively, change `nat_to_u64` to use a wider integer type, or make the `FieldsDisplayMessage` branch fall back to a string representation (as `GenericDisplayMessage` already does via `convert_tokens_to_string_representation`) rather than returning an error when the amount exceeds `u64::MAX`.

## Proof of Concept
Call `icrc21_canister_call_consent_message` on the ckETH ledger with:

```rust
method = "icrc1_transfer"
arg = Encode!(TransferArg {
    amount: Nat::from(u64::MAX) + Nat::from(1u64), // 18_446_744_073_709_551_616
    to: <any valid account>,
    fee: None, from_subaccount: None, memo: None, created_at_time: None,
})
user_preferences = ConsentMessageSpec {
    device_spec: Some(DisplayMessageType::FieldsDisplay),
    ...
}
```

Expected result:
```
Err(GenericError { error_code: 500, description: "Failed to convert tokens to u64" })
```

The same call with `device_spec = Some(GenericDisplay)` succeeds, confirming the bug is isolated to the `FieldsDisplayMessage` path. A unit test in `packages/icrc-ledger-types` can reproduce this deterministically without a running replica.

### Citations

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L11-17)
```rust
#[derive(CandidType, Deserialize, Eq, PartialEq, Debug, Serialize, Clone)]
pub enum Value {
    TokenAmount {
        decimals: u8,
        amount: u64,
        symbol: String,
    },
```

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L116-123)
```rust
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                "Amount".to_string(),
                Value::TokenAmount {
                    decimals,
                    amount: nat_to_u64(amount)?,
                    symbol: token_symbol.to_string(),
                },
            )),
```

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L153-158)
```rust
            ConsentMessage::FieldsDisplayMessage(fields_display) => {
                let token_amount = Value::TokenAmount {
                    decimals,
                    amount: nat_to_u64(amount)?,
                    symbol: token_symbol.to_string(),
                };
```

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L191-198)
```rust
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                "Requested allowance".to_string(),
                Value::TokenAmount {
                    decimals,
                    amount: nat_to_u64(amount)?,
                    symbol: token_symbol.to_string(),
                },
            )),
```

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L215-222)
```rust
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                "Existing allowance".to_string(),
                Value::TokenAmount {
                    decimals,
                    amount: nat_to_u64(expected_allowance)?,
                    symbol: token_symbol.to_string(),
                },
            )),
```

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L318-327)
```rust
fn convert_tokens_to_string_representation(
    tokens: Nat,
    decimals: u8,
) -> Result<String, Icrc21Error> {
    let tokens = tokens.0.to_f64().ok_or(Icrc21Error::GenericError {
        error_code: Nat::from(500_u64),
        description: "Failed to convert tokens to u64".to_owned(),
    })?;
    Ok(format!("{}", tokens / 10_f64.pow(decimals)))
}
```

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L329-334)
```rust
fn nat_to_u64(tokens: Nat) -> Result<u64, Icrc21Error> {
    tokens.0.to_u64().ok_or(Icrc21Error::GenericError {
        error_code: Nat::from(500_u64),
        description: "Failed to convert tokens to u64".to_owned(),
    })
}
```

**File:** packages/icrc-ledger-types/src/icrc21/lib.rs (L205-212)
```rust
                message.add_amount(self.amount, self.decimals, &token_symbol)?;
                message.add_account("To", receiver_account.to_string());
                message.add_fee(
                    Icrc21Function::Transfer,
                    self.ledger_fee,
                    self.decimals,
                    &token_symbol,
                )?;
```

**File:** packages/icrc-ledger-types/src/icrc21/lib.rs (L333-339)
```rust
    if consent_msg_request.arg.len() > MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize {
        return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description: format!(
                "The argument size is too large. The maximum allowed size is {MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES} bytes."
            ),
        }));
    }
```

**File:** rs/ledger_suite/icrc1/ledger/src/main.rs (L1189-1207)
```rust
#[update]
fn icrc21_canister_call_consent_message(
    consent_msg_request: ConsentMessageRequest,
) -> Result<ConsentInfo, Icrc21Error> {
    let caller_principal = ic_cdk::api::msg_caller();
    let ledger_fee = icrc1_fee();
    let token_symbol = icrc1_symbol();
    let token_name = icrc1_name();
    let decimals = icrc1_decimals();

    build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints(
        consent_msg_request,
        caller_principal,
        ledger_fee,
        token_symbol,
        token_name,
        decimals,
    )
}
```

**File:** rs/ledger_suite/icp/ledger/src/main.rs (L1478-1541)
```rust
#[update]
fn icrc21_canister_call_consent_message(
    consent_msg_request: ConsentMessageRequest,
) -> Result<ConsentInfo, Icrc21Error> {
    let caller_principal = caller();
    let ledger_fee = Nat::from(LEDGER.read().unwrap().transfer_fee.get_e8s());
    let token_symbol = LEDGER.read().unwrap().token_symbol.clone();
    let token_name = LEDGER.read().unwrap().token_name.clone();
    let decimals = ic_ledger_core::tokens::DECIMAL_PLACES as u8;

    if consent_msg_request.method == "transfer" {
        let TransferArgs {
            memo,
            amount,
            fee,
            from_subaccount,
            to,
            created_at_time: _,
        } = Decode!(&consent_msg_request.arg, TransferArgs).map_err(|e| {
            Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                description: format!("Failed to decode TransferArgs: {e}"),
            })
        })?;
        icrc21_check_fee(&Some(Nat::from(fee)), &ledger_fee)?;
        let from = if caller() == Principal::anonymous() {
            AccountOrId::AccountIdAddress(None)
        } else {
            let account = Account {
                owner: caller(),
                subaccount: from_subaccount.map(|sa| sa.0),
            };
            AccountOrId::AccountIdAddress(Some(AccountIdentifier::from(account).to_hex()))
        };
        let receiver = AccountIdentifier::from_slice(&to).map_err(|e| {
            Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                description: format!("Failed to parse receiver account id: {e}"),
            })
        })?;
        let args = GenericTransferArgs {
            from,
            receiver: AccountOrId::AccountIdAddress(Some(receiver.to_hex())),
            amount: Nat::from(amount.get_e8s()),
            memo: Some(GenericMemo::IntMemo(memo.0)),
        };
        build_icrc21_consent_info(
            consent_msg_request,
            caller_principal,
            ledger_fee,
            token_symbol,
            token_name,
            decimals,
            Some(args),
        )
    } else {
        build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints(
            consent_msg_request,
            caller_principal,
            ledger_fee,
            token_symbol,
            token_name,
            decimals,
        )
    }
}
```
