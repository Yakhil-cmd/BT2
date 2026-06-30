### Title
Permanent Loss of Bridged Tokens via `ExitToNear` Precompile When Receiver NEAR Account Is Unregistered — (`engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile (`0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`) allows any EVM user to bridge ETH or ERC-20 tokens to an arbitrary NEAR account ID. The precompile accepts any syntactically valid NEAR account ID as the receiver without verifying that the account is registered with the target NEP-141 token. When the downstream `ft_transfer` call fails (e.g., receiver not registered), and the compile-time `error_refund` feature is **not** enabled, the ERC-20 tokens are permanently burned in the EVM with no on-chain refund path, resulting in irreversible loss of user funds.

---

### Finding Description

The `ExitToNear` precompile's `run` method in `engine-precompiles/src/native.rs` parses a caller-supplied NEAR account ID via `parse_recipient`, validates only its syntactic format (length, character set), and then constructs a `ft_transfer` or `ft_transfer_call` promise targeting that account. [1](#0-0) 

For the legacy ERC-20 exit path (`flag = 0x1`, no `:unwrap` or Omni message), `exit_erc20_token_to_near` constructs an `ft_transfer` call with the caller-supplied `receiver_account_id`: [2](#0-1) 

The callback setup is conditional on the `error_refund` compile-time feature. When that feature is **absent**, `refund` is hardcoded to `None`: [3](#0-2) 

When both `refund` and `transfer_near` are `None`, `callback_args` equals `default()`, so the promise is created **without** a callback: [4](#0-3) 

This means: if the NEAR-side `ft_transfer` fails (e.g., receiver not registered with the NEP-141 token per NEP-145 storage standard), there is no on-chain mechanism to refund the already-burned ERC-20 tokens. The EVM state has been mutated (tokens burned), but the NEAR-side transfer never completed.

The same logic applies to the ETH (base token) exit path (`flag = 0x0`): [5](#0-4) 

The test suite explicitly documents this behavior: [6](#0-5) 

Lines 656–660 confirm: without `error_refund`, the exited tokens are gone permanently.

---

### Impact Explanation

**Critical — Permanent freezing / direct loss of user funds.**

When a user (or a contract acting on their behalf) calls `withdrawToNear` on an ERC-20 contract specifying a NEAR account that is not registered with the NEP-141 token:

1. The ERC-20 tokens are burned in the EVM (irreversible).
2. The `ft_transfer` promise to the NEP-141 contract fails at the NEAR level.
3. Without `error_refund`, no callback exists to re-mint or refund the tokens.
4. The NEP-141 tokens remain locked in Aurora's account; the user's ERC-20 balance is zero.

The funds are permanently inaccessible to the user.

---

### Likelihood Explanation

**Medium.** The entry path is fully unprivileged — any EVM account can call the `ExitToNear` precompile. Realistic triggering scenarios include:

- A user mistypes or copy-pastes an unregistered NEAR account ID.
- A user exits to a freshly created NEAR account that has not yet called `storage_deposit` on the NEP-141 contract.
- A smart contract on Aurora calls `ExitToNear` on behalf of a user, specifying a NEAR contract address that does not implement NEP-145 registration.

The `error_refund` feature is a compile-time opt-in. Deployments without it (which the codebase explicitly supports via `#[cfg(not(feature = "error_refund"))]` branches) are fully exposed.

---

### Recommendation

1. **Make `error_refund` mandatory in production builds**, or remove the conditional compilation and always set up the refund callback.
2. **Add a pre-flight existence/registration check**: before burning ERC-20 tokens, verify via a NEAR view call (or a stored registry) that the receiver account is registered with the target NEP-141 token.
3. **Alternatively**, adopt a two-phase exit: lock tokens in escrow first, then attempt `ft_transfer`, and only burn on confirmed success.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
EVM user → calls withdrawToNear("unregistered.near", amount) on ERC-20 contract
         → ERC-20 burns `amount` tokens and calls ExitToNear precompile
         → ExitToNear constructs ft_transfer("unregistered.near", amount) promise
         → ft_transfer fails (account not registered with NEP-141)
         → No callback (error_refund not enabled) → tokens permanently lost
```

**Exact code path:**

1. `ExitToNear::run` parses input → calls `exit_erc20_token_to_near` → returns `ft_transfer` args with `receiver_account_id = "unregistered.near"`. [7](#0-6) 

2. `callback_args.refund = None` (no `error_refund` feature) → `callback_args == default()` → `PromiseArgs::Create(transfer_promise)` with no failure callback. [4](#0-3) 

3. NEAR executes `ft_transfer("unregistered.near", amount)` → fails → no refund → ERC-20 tokens permanently lost.

The test at `engine-tests/src/tests/erc20_connector.rs:623–665` reproduces this exactly, confirming the `FT_EXIT_AMOUNT` tokens are unrecoverable when `error_refund` is absent. [8](#0-7)

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

**File:** engine-precompiles/src/native.rs (L444-446)
```rust
                ExitToNearParams::Erc20TokenParams(ref exit_params) => {
                    exit_erc20_token_to_near(context, exit_params, &self.io)?
                }
```

**File:** engine-precompiles/src/native.rs (L449-483)
```rust
        let callback_args = ExitToNearPrecompileCallbackArgs {
            #[cfg(feature = "error_refund")]
            refund: refund_call_args(&exit_to_near_params, &exit_event),
            #[cfg(not(feature = "error_refund"))]
            refund: None,
            transfer_near: transfer_near_args,
        };
        let attached_gas = if method == "ft_transfer_call" {
            costs::FT_TRANSFER_CALL_GAS
        } else {
            costs::FT_TRANSFER_GAS
        };

        let transfer_promise = PromiseCreateArgs {
            target_account_id: nep141_address,
            method,
            args: args.into_bytes(),
            attached_balance: Yocto::new(1),
            attached_gas,
        };

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

**File:** engine-precompiles/src/native.rs (L536-553)
```rust
        None => Ok((
            eth_connector_account_id,
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            format!(
                r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                exit_params.receiver_account_id,
                context.apparent_value.as_u128()
            ),
            events::ExitToNear::Legacy(ExitToNearLegacy {
                sender: Address::new(context.caller),
                erc20_address: events::ETH_ADDRESS,
                dest: exit_params.receiver_account_id.to_string(),
                amount: context.apparent_value,
            }),
            "ft_transfer".to_string(),
            None,
        )),
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

**File:** engine-tests/src/tests/erc20_connector.rs (L623-665)
```rust
    #[tokio::test]
    async fn test_exit_to_near_refund() {
        // Deploy Aurora; deploy NEP-141; bridge NEP-141 to ERC-20 on Aurora
        let TestExitToNearContext {
            ft_owner,
            ft_owner_address,
            nep_141,
            erc20,
            aurora,
            ..
        } = test_exit_to_near_common().await.unwrap();

        // Call exit on ERC-20; ft_transfer promise fails; expect refund on Aurora;
        exit_to_near(
            &ft_owner,
            // The ft_transfer will fail because this account is not registered with the NEP-141
            "unregistered.near",
            FT_EXIT_AMOUNT,
            &erc20,
            &aurora,
        )
        .await
        .unwrap();

        assert_eq!(
            nep_141_balance_of(&nep_141, &ft_owner.id()).await,
            FT_TOTAL_SUPPLY - FT_TRANSFER_AMOUNT
        );
        assert_eq!(
            nep_141_balance_of(&nep_141, &aurora.id()).await,
            FT_TRANSFER_AMOUNT
        );

        #[cfg(feature = "error_refund")]
        let balance = FT_TRANSFER_AMOUNT.into();
        // If the refund feature is not enabled then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();

        assert_eq!(
            erc20_balance(&erc20, ft_owner_address, &aurora).await,
            balance
        );
```
