The code trace is complete. Here is the analysis:

**Critical path confirmed:**

1. **Production build** uses `CARGO_FEATURES_BUILD = "contract"` — `error_refund` is **not** included. [1](#0-0) 

2. **Without `error_refund`**, `callback_args.refund` is hardcoded to `None`: [2](#0-1) 

3. For the base-token (ETH) path with no message, `transfer_near_args` is also `None`: [3](#0-2) 

4. Both fields `None` means `callback_args == ExitToNearPrecompileCallbackArgs::default()`, so the branch at line 470 takes `PromiseArgs::Create` — **no callback is scheduled**: [4](#0-3) 

5. The test `test_exit_to_near_eth_refund` explicitly confirms the permanent loss when `error_refund` is absent: [5](#0-4) 

6. `ExitToNearPrecompileCallbackArgs` derives `Default` with both fields `None`: [6](#0-5) 

---

### Title
Permanent ETH Freeze via `ExitToNear` Precompile When `error_refund` Feature Is Disabled — (`engine-precompiles/src/native.rs`)

### Summary
When the production WASM is built without the `error_refund` feature (the default production configuration), any EVM user can permanently destroy ETH by calling the `ExitToNear` precompile with flag `0x0` targeting a NEAR account that has no NEP-141 storage deposit. The ETH is debited from the caller's EVM balance, the `ft_transfer` promise is scheduled with no callback, and when the promise fails on NEAR there is no mechanism to refund the caller.

### Finding Description
In `ExitToNear::run`, after `exit_base_token_to_near` returns `transfer_near_args = None` for the plain `ft_transfer` path, `callback_args` is constructed as:

```rust
ExitToNearPrecompileCallbackArgs {
    refund: None,          // hardcoded when error_refund feature is off
    transfer_near: None,   // returned by exit_base_token_to_near for flag=0x0, no message
}
```

This equals `ExitToNearPrecompileCallbackArgs::default()`, so the guard at line 470 selects `PromiseArgs::Create(transfer_promise)` — a bare `ft_transfer` with no callback. The EVM state (ETH debit) is committed before the NEAR promise executes. If `ft_transfer` fails (e.g., recipient not registered with the eth-connector NEP-141), the failure is silently dropped and the ETH is gone.

The `error_refund` feature exists precisely to attach a `RefundCallArgs` and schedule `exit_to_near_precompile_callback`, but the production build (`CARGO_FEATURES_BUILD = "contract"`) does not enable it.

### Impact Explanation
**Critical — Permanent freezing of funds.** Any EVM user who calls `ExitToNear` with flag `0x0` targeting an unregistered NEAR account loses their ETH permanently. The ETH is debited from the EVM balance, the NEP-141 balance of the recipient remains zero, and no refund path exists in the production binary.

### Likelihood Explanation
High. The trigger condition — a recipient NEAR account without a storage deposit on the eth-connector NEP-141 — is trivially reachable by any user (e.g., a freshly created NEAR account, a mistyped account ID, or any account that has never interacted with the eth-connector). No privilege is required; a standard EVM transaction suffices.

### Recommendation
Enable the `error_refund` feature in the production build by changing `CARGO_FEATURES_BUILD` from `"contract"` to `"contract,error_refund"` in `Makefile.toml`. This causes `refund_call_args` to populate `callback_args.refund`, making `callback_args != default()`, which schedules the `exit_to_near_precompile_callback` that calls `engine::refund_on_error` on failure. [7](#0-6) 

Alternatively, remove the `#[cfg(not(feature = "error_refund"))] refund: None` branch and make the refund path unconditional for the base-token case.

### Proof of Concept
The existing test `test_exit_to_near_eth_refund` in `engine-tests/src/tests/erc20_connector.rs` already proves the invariant break. Run it **without** the `error_refund` feature:

```bash
cargo test -p aurora-engine-tests test_exit_to_near_eth_refund
# (no --features error_refund)
```

The test asserts:
```rust
#[cfg(not(feature = "error_refund"))]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
assert_eq!(eth_balance_of(signer_address, &aurora).await, expected_balance);
```

This confirms `ETH_EXIT_AMOUNT` is permanently destroyed: the signer's ETH balance decreased, the recipient's NEP-141 balance is zero, and no refund occurred — matching the production binary behavior exactly. [8](#0-7)

### Citations

**File:** Makefile.toml (L8-8)
```text
CARGO_FEATURES_BUILD = "contract"
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

**File:** engine-tests/src/tests/erc20_connector.rs (L765-780)
```rust
        // check balances
        assert_eq!(
            nep_141_balance_of(aurora.as_raw_contract(), &exit_account_id.parse().unwrap()).await,
            0
        );

        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);

        assert_eq!(
            eth_balance_of(signer_address, &aurora).await,
            expected_balance
        );
```

**File:** engine-types/src/parameters/connector.rs (L130-134)
```rust
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, Default)]
pub struct ExitToNearPrecompileCallbackArgs {
    pub refund: Option<RefundCallArgs>,
    pub transfer_near: Option<TransferNearArgs>,
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
