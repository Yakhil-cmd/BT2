### Title
Ethereum `value` field silently absorbed (never spent, never refunded) on `AddKey`/`DeleteKey` RLP-emulated actions in the Wallet Contract - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/types.rs`)

### Summary
The `near-wallet-contract` translates Ethereum-style RLP transactions into NEAR actions. Just like the InfinityExchange `currency`/`msg.value` mismatch, the wallet contract computes a NEAR-value contribution (`additional_value`, derived from the Ethereum transaction's `value` field, analogous to `msg.value`) and passes it into `Action::try_into_near_action`, but for the `AddKey` and `DeleteKey` action kinds this value is completely discarded rather than being applied to the resulting NEAR action or refunded to the account balance.

### Finding Description
`internal::parse_rlp_tx_to_action` computes `additional_value` purely from the Ethereum transaction's `value` field (`tx.value.raw().low_u128().saturating_mul(MAX_YOCTO_NEAR.into())`) and unconditionally forwards it to `Action::try_into_near_action(additional_value)`: [1](#0-0) 

`try_into_near_action` only consumes `additional_value` for `FunctionCall` and `Transfer` variants (adding it to `deposit`). For `AddKey` and `DeleteKey` it is entirely ignored — no deposit field exists on those NEAR actions and `additional_value` is simply dropped: [2](#0-1) 

Critically, `parse_tx_data` validates `yocto_near < MAX_YOCTO_NEAR` for the `FUNCTION_CALL_SELECTOR` and `TRANSFER_SELECTOR` branches, but performs **no equivalent validation on `tx.value` for `ADD_KEY_SELECTOR` / `DELETE_KEY_SELECTOR`** — there is no check anywhere that `tx.value == 0` for these two action kinds: [3](#0-2) 

This is the direct analog of the reported bug: exactly like `takeOrders`/`takeMultipleOneOrders` only checking `msg.value >= totalPrice` for the ETH-`currency` branch and never rejecting nonzero `msg.value` on the ERC20-`currency` branch, the wallet contract validates/consumes the "value" only for `FunctionCall`/`Transfer` action kinds and silently swallows it for `AddKey`/`DeleteKey`.

Because `rlp_execute` is `#[payable]`, an actual attached NEAR deposit funds the contract's balance regardless of which action is ultimately executed: [4](#0-3) 
and the resulting `Promise` for `AddKey`/`DeleteKey` never transfers or refunds any of that value: [5](#0-4) 

The `CallerDeposit` refund mechanism only fires when the downstream cross-contract-call promise **fails**; on success (which is exactly the case for a correctly-formed `AddKey`/`DeleteKey` transaction with an accidentally nonzero `tx.value`) the deposit is not refunded, per the confirmed behavior in `test_caller_refunds`: [6](#0-5) 

### Impact Explanation
A wallet owner (or their relayer) constructing an Ethereum-style `AddKey`/`DeleteKey` transaction who sets a nonzero `value` field (e.g., by mistake, a wallet UI bug, or a fee-estimation script that always populates `value`) will have that NEAR value permanently retained/lost inside the wallet contract's own balance — it is not applied to any action, not transferred to any account, and not refunded. This is a fund-loss condition reachable directly from a signed, user-originated Ethereum transaction routed through a normal, unprivileged `rlp_execute` call; no validator or malicious-node behavior is required.

### Likelihood Explanation
Likelihood is comparable to the original finding: it depends on user/tooling error (populating `value` on what should be a value-less action), but because `AddKey`/`DeleteKey` share the same code path and transaction format (`NormalizedEthTransaction` with a `value` field) as `FunctionCall`/`Transfer`, and because no validation rejects a nonzero value for these two selectors (unlike the `yocto_near` check that does exist for the other two), the probability of this occurring is non-negligible for any wallet/relayer implementation that does not itself special-case zero-value transactions for key-management actions.

### Recommendation
Mirror the `yocto_near >= MAX_YOCTO_NEAR` rejection pattern already used for `FUNCTION_CALL_SELECTOR`/`TRANSFER_SELECTOR`: in `parse_tx_data`, explicitly reject (return a `UserError`, e.g. a new `NonZeroValueNotSupported` variant) any `ADD_KEY_SELECTOR` or `DELETE_KEY_SELECTOR` transaction where `tx.value != 0`, before constructing the `Action::AddKey`/`Action::DeleteKey`. Alternatively, have `try_into_near_action` return an error when `additional_value > 0` for these variants instead of silently discarding it.

### Proof of Concept
1. Deploy an eth-implicit wallet contract account and derive its Ethereum-style address.
2. Craft an EIP-2930/legacy Ethereum transaction whose `data` field ABI-encodes an `AddKey` (or `DeleteKey`) call (selector `0x753ce5ab` / `0x3fc6d404`) and whose `value` field is set to a nonzero amount (as done for `Transfer`/`FunctionCall` in `create_rlp_execute_tx`, but targeting the key-management selectors instead): [7](#0-6) 
3. Sign the transaction with the wallet's secret key and submit it via `rlp_execute`, attaching the corresponding NEAR deposit (`value * MAX_YOCTO_NEAR`) as `attached_deposit`, similar to the flow in `rlp_execute_from`: [8](#0-7) 
4. Observe that the `AddKey`/`DeleteKey` action succeeds, the access key is added/deleted as requested, but the attached NEAR value is neither transferred to any recipient nor refunded to the caller — it remains stuck in the wallet contract's balance, confirmed by the absence of any refund path in `action_to_promise` for `AddKey`/`DeleteKey` and the fact that `CallerDeposit` refunds only trigger on promise failure, not success.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L159-165)
```rust
    validate_tx_value(&tx)?;

    // Call to `low_u128` here is safe because of the validation done in `validate_tx_value`
    let near_action = action
        .try_into_near_action(tx.value.raw().low_u128().saturating_mul(MAX_YOCTO_NEAR.into()))?;

    Ok((near_action, transaction_kind))
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L272-309)
```rust
        ADD_KEY_SELECTOR => {
            let (
                public_key_kind,
                public_key,
                nonce,
                is_full_access,
                is_limited_allowance,
                allowance,
                receiver_id,
                method_names,
            ) = ethabi_utils::abi_decode(&ADD_KEY_SIGNATURE, &tx.data[4..])?;
            Ok((
                Action::AddKey {
                    public_key_kind,
                    public_key,
                    nonce,
                    is_full_access,
                    is_limited_allowance,
                    allowance,
                    receiver_id,
                    method_names,
                },
                ParsableTransactionKind::SelfNearNativeAction,
            ))
        }
        DELETE_KEY_SELECTOR => {
            let (public_key_kind, public_key) =
                ethabi_utils::abi_decode(&DELETE_KEY_SIGNATURE, &tx.data[4..])?;
            Ok((
                Action::DeleteKey { public_key_kind, public_key },
                ParsableTransactionKind::SelfNearNativeAction,
            ))
        }
        _ => {
            let (action, emulation_kind) = eth_emulation::try_emulation(target, tx, fee, context)?;
            Ok((action, ParsableTransactionKind::EthEmulation(emulation_kind)))
        }
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/types.rs (L226-299)
```rust
impl Action {
    pub fn value(&self) -> NearToken {
        match self {
            Action::FunctionCall { yocto_near, .. } => {
                NearToken::from_yoctonear((*yocto_near).into())
            }
            Action::Transfer { yocto_near, .. } => NearToken::from_yoctonear((*yocto_near).into()),
            Action::AddKey { .. } => NearToken::from_yoctonear(0),
            Action::DeleteKey { .. } => NearToken::from_yoctonear(0),
        }
    }

    pub fn try_into_near_action(
        self,
        additional_value: u128,
    ) -> Result<near_action::Action, Error> {
        let action = match self {
            Action::FunctionCall { receiver_id: _, method_name, args, gas, yocto_near } => {
                let action = FunctionCallAction {
                    method_name,
                    args,
                    gas: Gas::from_gas(gas),
                    deposit: NearToken::from_yoctonear(
                        additional_value.saturating_add(yocto_near.into()),
                    ),
                };
                near_action::Action::FunctionCall(action)
            }
            Action::Transfer { receiver_id: _, yocto_near } => {
                let action = TransferAction {
                    deposit: NearToken::from_yoctonear(
                        additional_value.saturating_add(yocto_near.into()),
                    ),
                };
                near_action::Action::Transfer(action)
            }
            Action::AddKey {
                public_key_kind,
                public_key,
                nonce,
                is_full_access,
                is_limited_allowance,
                allowance,
                receiver_id,
                method_names,
            } => {
                let public_key = construct_public_key(public_key_kind, &public_key)?;
                let access_key = if is_full_access {
                    AccessKey { nonce, permission: AccessKeyPermission::FullAccess }
                } else {
                    let allowance = if is_limited_allowance { Some(allowance) } else { None };
                    AccessKey {
                        nonce,
                        permission: AccessKeyPermission::FunctionCall(FunctionCallPermission {
                            allowance: allowance.map(NearToken::from_yoctonear),
                            receiver_id: receiver_id
                                .parse()
                                .map_err(|_| Error::User(UserError::InvalidAccessKeyAccountId))?,
                            method_names,
                        }),
                    }
                };
                let action = AddKeyAction { public_key, access_key };
                near_action::Action::AddKey(action)
            }
            Action::DeleteKey { public_key_kind, public_key } => {
                let action = DeleteKeyAction {
                    public_key: construct_public_key(public_key_kind, &public_key)?,
                };
                near_action::Action::DeleteKey(action)
            }
        };
        Ok(action)
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L88-93)
```rust
    #[payable]
    pub fn rlp_execute(
        &mut self,
        target: AccountId,
        tx_bytes_b64: String,
    ) -> PromiseOrValue<ExecuteResponse> {
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L475-500)
```rust
fn action_to_promise(target: AccountId, action: near_action::Action) -> Result<Promise, Error> {
    match action {
        near_action::Action::FunctionCall(action) => Ok(Promise::new(target).function_call(
            action.method_name,
            action.args,
            action.deposit,
            action.gas,
        )),
        near_action::Action::Transfer(action) => Ok(Promise::new(target).transfer(action.deposit)),
        near_action::Action::AddKey(action) => match action.access_key.permission {
            near_action::AccessKeyPermission::FullAccess => {
                Err(Error::User(UserError::UnsupportedAction(UnsupportedAction::AddFullAccessKey)))
            }
            near_action::AccessKeyPermission::FunctionCall(access) => Ok(Promise::new(target)
                .add_access_key_allowance_with_nonce(
                    action.public_key,
                    access.allowance.and_then(Allowance::limited).unwrap_or(Allowance::Unlimited),
                    access.receiver_id,
                    access.method_names.join(","),
                    action.access_key.nonce,
                )),
        },
        near_action::Action::DeleteKey(action) => {
            Ok(Promise::new(target).delete_key(action.public_key))
        }
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/tests/sanity.rs (L215-226)
```rust
    // External caller does not get a refund when their tokens are spent
    let pre_tx_account_balance = post_tx_account_balance;
    let receiver_id = address_registrar.id();
    let result = wallet_contract
        .rlp_execute_from(&caller, receiver_id.as_str(), &create_tx(receiver_id, 1), deposit_amount)
        .await?;
    assert!(result.success);
    let post_tx_account_balance = caller.view_account().await?.balance;
    assert!(
        pre_tx_account_balance.as_yoctonear() - post_tx_account_balance.as_yoctonear()
            >= deposit_amount.as_yoctonear()
    );
```

**File:** integration-tests/src/tests/features/wallet_contract.rs (L348-374)
```rust
pub fn create_rlp_execute_tx(
    target: &AccountIdRef,
    mut action: Action,
    nonce: u64,
    eth_implicit_account: &AccountIdRef,
    secret_key: &SecretKey,
    near_signer: &NearSigner<'_>,
    env: &TestEnv,
) -> SignedTransaction {
    const CHAIN_ID: u64 = 399;
    // handles 24 vs 18 decimal mismatch between $NEAR and $ETH
    const MAX_YOCTO_NEAR: u128 = 1_000_000;

    // Construct Eth transaction from user's intended action
    let value = match &mut action {
        Action::Transfer(tx) => {
            let raw_amount = tx.deposit;
            tx.deposit = Balance::from_yoctonear(raw_amount.as_yoctonear() % MAX_YOCTO_NEAR);
            Wei::new_u128(raw_amount.as_yoctonear() / MAX_YOCTO_NEAR)
        }
        Action::FunctionCall(fn_call) => {
            let raw_amount = fn_call.deposit;
            fn_call.deposit = Balance::from_yoctonear(raw_amount.as_yoctonear() % MAX_YOCTO_NEAR);
            Wei::new_u128(raw_amount.as_yoctonear() / MAX_YOCTO_NEAR)
        }
        _ => Wei::zero(),
    };
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/tests/utils/test_context.rs (L53-74)
```rust
    pub async fn rlp_execute_from(
        &self,
        caller: &Account,
        target: &str,
        tx: &EthTransactionKind,
        attached_deposit: NearToken,
    ) -> anyhow::Result<ExecuteResponse> {
        let result: ExecuteResponse = caller
            .call(self.inner.id(), RLP_EXECUTE)
            .args_json(serde_json::json!({
                "target": target,
                "tx_bytes_b64": codec::encode_b64(&codec::rlp_encode(tx))
            }))
            .max_gas()
            .deposit(attached_deposit)
            .transact()
            .await?
            .into_result()?
            .json()?;

        Ok(result)
    }
```
