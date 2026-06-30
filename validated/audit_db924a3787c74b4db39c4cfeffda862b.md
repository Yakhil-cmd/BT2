### Title
Unchecked Precompile Call Return Value in `withdrawToNear`/`withdrawToEthereum` Causes Permanent Token Burn Without Withdrawal - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` permanently burn a user's ERC-20 tokens **before** calling the exit precompile, and neither contract checks the return value of that call. If the precompile call fails for any reason (invalid recipient account ID, unregistered ERC-20 mapping, amount overflow, etc.), the EVM call returns `0` silently, the tokens are destroyed, and no corresponding NEP-141 withdrawal is ever scheduled. The `error_refund` callback mechanism does not cover this failure path.

---

### Finding Description

In both contracts, `withdrawToNear` and `withdrawToEthereum` follow the same pattern:

**`EvmErc20.sol` lines 53–63 / `EvmErc20V2.sol` lines 53–64 (`withdrawToNear`):**

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    address sender = _msgSender();
    _burn(sender, amount);                          // ← state change: tokens destroyed

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
    uint input_size = 1 + 20 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked — silent failure
    }
}
``` [1](#0-0) [2](#0-1) 

The same pattern applies to `withdrawToEthereum` in both contracts. [3](#0-2) [4](#0-3) 

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) returns `Err(ExitError::...)` — causing the EVM `call()` to return `0` — in several reachable conditions:

- `parse_recipient` fails on an invalid NEAR account ID (`ERR_INVALID_RECEIVER_ACCOUNT_ID`)
- `get_nep141_from_erc20` fails when the ERC-20 has no registered NEP-141 mapping
- `parse_amount` fails when `amount > u128::MAX`
- `context.apparent_value != 0` for an ERC-20 exit (`ERR_ETH_ATTACHED_FOR_ERC20_EXIT`) [5](#0-4) [6](#0-5) 

When any of these conditions trigger, the precompile returns an error, the EVM `call()` returns `0`, but because `res` is never inspected, the Solidity function returns normally. The `_burn` has already executed and is not rolled back.

**Why the `error_refund` callback does not help here:**

The `exit_to_near_precompile_callback` refund path is only reached when the precompile call itself **succeeds** (emits a promise log) and the subsequent `ft_transfer` NEAR promise **fails**. When the precompile call returns an error to the EVM, no promise log is emitted, no callback is scheduled, and the refund branch is never reached. [7](#0-6) [8](#0-7) 

This is confirmed by the existing test comment:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [9](#0-8) 

Even with `error_refund` enabled, the refund only covers the promise-failure path, not the precompile-call-failure path.

---

### Impact Explanation

A user who calls `withdrawToNear` or `withdrawToEthereum` with an input that causes the precompile to return an error (e.g., a malformed or too-long NEAR account ID as `recipient`) will have their ERC-20 tokens permanently burned with no corresponding NEP-141 transfer scheduled. The tokens are irrecoverably destroyed. This is a **permanent freezing (destruction) of user funds** with no recovery path.

Additionally, this creates a persistent accounting discrepancy: the ERC-20 total supply decreases, but the Aurora engine's NEP-141 balance does not, breaking the 1:1 backing invariant of the bridge.

---

### Likelihood Explanation

The `recipient` parameter in `withdrawToNear` is a raw `bytes` value supplied by the caller. NEAR account IDs have strict validity rules (max 64 characters, allowed character set, no leading/trailing dots, etc.). A user who passes an Ethereum hex address, a too-long string, or a string with invalid characters will silently lose their tokens. This is a realistic user-facing error path with no on-chain protection. The precompile enforces validity but the ERC-20 contract discards the failure signal.

---

### Recommendation

Check the return value of the precompile `call()` and revert on failure in both `withdrawToNear` and `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures that if the precompile rejects the call for any reason, the entire transaction reverts, the `_burn` is rolled back, and the user's tokens are preserved.

---

### Proof of Concept

1. Deploy `EvmErc20V2` (or `EvmErc20`) with a registered NEP-141 mapping.
2. Mint `1000` tokens to `alice`.
3. `alice` calls `withdrawToNear("invalid account id!!!", 1000)` — the `!` characters make this an invalid NEAR account ID.
4. Inside the function: `_burn(alice, 1000)` executes, reducing `alice`'s balance to `0` and total supply by `1000`.
5. The precompile call is made; `parse_recipient` returns `Err(ExitError::Other("ERR_INVALID_RECEIVER_ACCOUNT_ID"))`.
6. The EVM `call()` returns `0`; `res` is never checked; the function returns normally.
7. Result: `alice` has `0` tokens, total supply decreased by `1000`, no NEP-141 transfer was scheduled, no refund issued. Funds are permanently destroyed. [1](#0-0) [10](#0-9)

### Citations

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-64)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        address sender = _msgSender();
        _burn(sender, amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
        uint input_size = 1 + 20 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L66-77)
```text
    function withdrawToEthereum(address recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes20 recipient_b = bytes20(recipient);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient_b);
        uint input_size = 1 + 32 + 20;

        assembly {
            let res := call(gas(), 0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-63)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L65-76)
```text
    function withdrawToEthereum(address recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes20 recipient_b = bytes20(recipient);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient_b);
        uint input_size = 1 + 32 + 20;

        assembly {
            let res := call(gas(), 0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

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

**File:** engine-precompiles/src/native.rs (L419-447)
```rust
        let exit_to_near_params = ExitToNearParams::try_from(input)?;

        let (nep141_address, args, exit_event, method, transfer_near_args) =
            match exit_to_near_params {
                // ETH(base) token transfer
                //
                // Input slice format:
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 (base) tokens, or also can contain the `:unwrap` suffix in case of
                //  withdrawing wNEAR, or another message of JSON in case of OMNI, or address of
                //  receiver in case of transfer tokens to another engine contract.
                ExitToNearParams::BaseToken(ref exit_params) => {
                    let eth_connector_account_id = self.get_eth_connector_contract_account()?;
                    exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
                }
                // ERC-20 token transfer
                //
                // This precompile branch is expected to be called from the ERC-20 burn function.
                //
                // Input slice format:
                //  amount (U256 big-endian bytes) - the amount that was burned
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 tokens, or also can contain the `:unwrap` suffix in case of withdrawing
                //  wNEAR, or another message of JSON in case of OMNI, or address of receiver in case
                //  of transfer tokens to another engine contract.
                ExitToNearParams::Erc20TokenParams(ref exit_params) => {
                    exit_erc20_token_to_near(context, exit_params, &self.io)?
                }
            };
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

**File:** engine-precompiles/src/native.rs (L576-583)
```rust
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }

    let erc20_address = context.caller; // because ERC-20 contract calls the precompile.
    let nep141_account_id = get_nep141_from_erc20(erc20_address.as_bytes(), io)?;
```

**File:** engine/src/contract_methods/connector.rs (L214-241)
```rust
        let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
            if let Some(args) = args.transfer_near {
                let action = PromiseAction::Transfer {
                    amount: Yocto::new(args.amount),
                };
                let promise = PromiseBatchAction {
                    target_account_id: args.target_account_id,
                    actions: vec![action],
                };

                // Safety: this call is safe because it comes from the exit to near precompile, not users.
                // The call is to transfer the unwrapped wNEAR tokens.
                let promise_id = handler.promise_create_batch(&promise);
                handler.promise_return(promise_id);
            }

            None
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
        } else {
            None
```

**File:** engine-tests/src/tests/erc20_connector.rs (L656-665)
```rust
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
