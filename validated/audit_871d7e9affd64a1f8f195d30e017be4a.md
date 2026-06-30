### Title
Lack of Destination NEAR Account Validation in `ExitToNear` Precompile Enables Permanent Token Loss - (File: `engine-precompiles/src/native.rs`)

### Summary
The `ExitToNear` precompile accepts any syntactically valid NEAR account ID as the bridge-out destination without validating it against a whitelist of accounts that have storage registered on the target NEP-141 contract. In the legacy ERC-20 exit path compiled without the `error_refund` Cargo feature, a failed downstream `ft_transfer` is silently dropped: the ERC-20 tokens are already burned on Aurora and are never credited on NEAR, resulting in permanent loss.

### Finding Description
`ExitToNear::run()` delegates destination parsing to `parse_recipient()`. [1](#0-0) 

`parse_recipient()` only enforces NEAR account-ID character-set and length rules via `AccountId::validate()`. There is no check against any whitelist of accounts known to have storage registered on the target NEP-141 contract. [2](#0-1) 

In the legacy ERC-20 exit branch (`exit_erc20_token_to_near`), the flow is:

1. The ERC-20 contract burns the caller's tokens and calls the precompile.
2. The precompile builds a `ft_transfer` promise targeting the caller-supplied `receiver_account_id`. [3](#0-2) 

3. `callback_args` is constructed. Without the `error_refund` feature, `refund` is `None` and `transfer_near` is `None`, so `callback_args == ExitToNearPrecompileCallbackArgs::default()`. [4](#0-3) 

4. Because `callback_args == default()`, the promise is emitted as a bare `PromiseArgs::Create` — **no failure callback is attached**. [5](#0-4) 

5. If the NEP-141 `ft_transfer` fails (recipient has no storage deposit, or the account does not exist on NEAR), the failure is silently dropped. The ERC-20 tokens remain burned on Aurora and are never minted on NEAR.

The `error_refund` feature is the only guard against this outcome: [4](#0-3) 

When that feature is absent, the callback branch in `exit_to_near_precompile_callback` that would re-mint the tokens is never reached. [6](#0-5) 

### Impact Explanation
**Permanent freezing/loss of user funds (Critical).** Any EVM user who calls the `ExitToNear` precompile — directly or via an ERC-20 `withdraw` function — with a destination NEAR account that lacks a storage deposit on the target NEP-141 contract will permanently lose their tokens. The tokens are burned on Aurora and never credited on NEAR, with no on-chain recovery path when `error_refund` is absent.

### Likelihood Explanation
The entry path is fully unprivileged: any EVM account can call an ERC-20 contract's withdraw function and supply an arbitrary destination NEAR account ID. The only syntactic constraint is that the account ID passes NEAR's character-set and length rules (`AccountId::validate()`). Non-existent accounts and accounts without storage deposits are common (any freshly generated NEAR account ID that has never been funded). Likelihood is **medium-to-high** whenever the `error_refund` Cargo feature is not compiled into the production build.

### Recommendation
1. **Whitelist valid destination accounts**: Before burning ERC-20 tokens, validate that the destination NEAR account has storage registered on the target NEP-141 contract (e.g., via a cross-contract view call or an on-chain registry).
2. **Always compile `error_refund`**: Ensure the `error_refund` Cargo feature is unconditionally enabled in production builds so that a failed NEAR-side transfer triggers re-minting of the burned ERC-20 tokens to the original sender.

### Proof of Concept
```
// Attacker: EVM user holding ERC-20 tokens mapped to some NEP-141.

// Step 1: call the ERC-20 withdraw function specifying a non-existent NEAR account.
//   ExitToNear precompile input (ERC-20 path):
//     [0x01]                    // flag: ERC-20 exit
//     ++ amount.to_big_endian() // e.g. 1000 tokens
//     ++ b"ghost.near"          // syntactically valid but unregistered account

// Step 2: ERC-20 tokens are burned on Aurora (irreversible at this point).

// Step 3: ft_transfer("ghost.near", 1000) is scheduled on the NEP-141 contract.

// Step 4: ft_transfer panics — "ghost.near" has no storage deposit.

// Step 5: No callback exists (error_refund not compiled in).
//         Tokens are permanently lost — burned on Aurora, never minted on NEAR.
```

### Citations

**File:** engine-precompiles/src/native.rs (L359-378)
```rust
fn parse_recipient(recipient: &[u8]) -> Result<Recipient<'_>, ExitError> {
    let recipient = str::from_utf8(recipient)
        .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?;
    let (receiver_account_id, message) = recipient.split_once(':').map_or_else(
        || (recipient, None),
        |(recipient, msg)| {
            if msg == UNWRAP_WNEAR_MSG {
                (recipient, Some(Message::UnwrapWnear))
            } else {
                (recipient, Some(Message::Omni(msg)))
            }
        },
    );

    Ok(Recipient {
        receiver_account_id: receiver_account_id
            .parse()
            .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?,
        message,
    })
```

**File:** engine-precompiles/src/native.rs (L449-455)
```rust
        let callback_args = ExitToNearPrecompileCallbackArgs {
            #[cfg(feature = "error_refund")]
            refund: refund_call_args(&exit_to_near_params, &exit_event),
            #[cfg(not(feature = "error_refund"))]
            refund: None,
            transfer_near: transfer_near_args,
        };
```

**File:** engine-precompiles/src/native.rs (L470-483)
```rust
        let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
            PromiseArgs::Create(transfer_promise)
        } else {
            PromiseArgs::Callback(PromiseWithCallbackArgs {
                base: transfer_promise,
                callback: PromiseCreateArgs {
                    target_account_id: self.current_account_id.clone(),
                    method: "exit_to_near_precompile_callback".to_string(),
                    args: borsh::to_vec(&callback_args).unwrap(),
                    attached_balance: Yocto::new(0),
                    attached_gas: costs::EXIT_TO_NEAR_CALLBACK_GAS,
                },
            })
        };
```

**File:** engine-precompiles/src/native.rs (L627-646)
```rust
        _ => {
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            (
                nep141_account_id,
                format!(
                    r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                    exit_params.receiver_account_id,
                    exit_params.amount.as_u128()
                ),
                "ft_transfer",
                None,
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
```

**File:** engine/src/contract_methods/connector.rs (L231-239)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
```
