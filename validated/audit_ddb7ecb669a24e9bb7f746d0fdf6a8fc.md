### Title
ERC-20 and ETH Tokens Permanently Lost When `exit_to_near` NEAR Transfer Fails Without `error_refund` Feature — (File: `engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile burns ERC-20 tokens (or deducts ETH) from a user's EVM balance and schedules a NEAR `ft_transfer` promise. Without the `error_refund` compile-time feature, no failure-handling callback is registered. If the NEAR `ft_transfer` fails — for example, because the recipient NEAR account is not registered with the NEP-141 contract — the burned tokens are permanently unrecoverable. This is the direct analog of the Booster pattern: value is irrevocably transferred into a one-way sink with no retrieval path.

---

### Finding Description

In `ExitToNear::run`, after parsing the exit parameters, a `callback_args` struct is constructed: [1](#0-0) 

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
```

`transfer_near_args` is `Some(...)` **only** for the wNEAR-unwrap path. For the ERC-20 exit path and the ETH base-token exit path it is `None`: [2](#0-1) 

The promise is then created conditionally: [3](#0-2) 

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback at all
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
```

When `error_refund` is **not** compiled in and the exit is not a wNEAR unwrap, `callback_args` equals `default()`, so a bare `PromiseArgs::Create` is emitted with **no failure callback**. The EVM state change (token burn / ETH deduction) has already been committed. If the downstream `ft_transfer` promise fails, there is no path to re-mint the tokens or credit the user.

The developers explicitly acknowledged the symmetric risk for the ERC-20 exit path (ETH attached to an ERC-20 exit): [4](#0-3) 

> "the funds will be locked in the address of the precompile without any possibility to withdraw them in the future"

They added a guard for that sub-case, but the guard does not cover the scenario where the NEAR-side `ft_transfer` itself fails after the EVM burn has been committed.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

- The ERC-20 tokens are burned (supply permanently reduced) in the EVM.
- The equivalent NEP-141 tokens remain in Aurora's contract balance, inaccessible to the user.
- The user holds neither ERC-20 tokens nor NEP-141 tokens.
- There is no admin escape hatch, no re-mint function, and no callback to reverse the burn.

The test suite confirms this explicitly: [5](#0-4) 

```rust
#[cfg(feature = "error_refund")]
let balance = FT_TRANSFER_AMOUNT.into();
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
```

The same permanent-loss behavior applies to ETH base-token exits: [6](#0-5) 

---

### Likelihood Explanation

**High.** NEAR NEP-141 contracts require explicit `storage_deposit` registration before an account can receive tokens. Any user who calls `exit_to_near` targeting a NEAR account that has not been registered with the relevant NEP-141 contract will trigger a failed `ft_transfer`. This is a routine operational mistake (e.g., sending to a freshly created NEAR account, a DAO account, or any account that has never interacted with the specific NEP-141). No special attacker capability is required — the user only needs to submit an EVM transaction calling the ERC-20's `withdrawToNear` function.

---

### Recommendation

Remove the compile-time gating of the refund callback. The failure-handling callback (`exit_to_near_precompile_callback`) should be registered unconditionally for every `exit_to_near` call that burns user value, regardless of whether `error_refund` is a build feature. The callback already exists and handles the refund correctly when present; the only change needed is to make its registration the default, non-optional behavior. [7](#0-6) 

---

### Proof of Concept

1. User holds 100 units of a bridged ERC-20 token on Aurora.
2. User calls `withdrawToNear("unregistered.near", 100)` on the ERC-20 contract.
3. The ERC-20 contract calls the `exit_to_near` precompile (`ExitToNearParams::Erc20TokenParams`).
4. `exit_erc20_token_to_near` returns `transfer_near_args = None` (not a wNEAR unwrap).
5. Without `error_refund`, `callback_args == default()` → `PromiseArgs::Create(ft_transfer_promise)` with no callback.
6. The EVM burn is committed: user's ERC-20 balance drops to 0.
7. The NEAR `ft_transfer` to `"unregistered.near"` fails (account not registered).
8. No callback fires; no re-mint occurs.
9. User's 100 ERC-20 tokens are permanently destroyed; the 100 NEP-141 tokens remain locked in Aurora's balance with no user-accessible recovery path.

Confirmed by `test_exit_to_near_refund` in: [8](#0-7)

### Citations

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

**File:** engine-precompiles/src/native.rs (L572-580)
```rust
    // In case of withdrawing ERC-20 tokens, the `apparent_value` should be zero. In opposite way
    // the funds will be locked in the address of the precompile without any possibility
    // to withdraw them in the future. So, in case if the `apparent_value` is not zero, the error
    // will be returned to prevent that.
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }
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

**File:** engine-tests/src/tests/erc20_connector.rs (L623-666)
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
    }
```

**File:** engine-tests/src/tests/erc20_connector.rs (L771-776)
```rust
        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);

```
