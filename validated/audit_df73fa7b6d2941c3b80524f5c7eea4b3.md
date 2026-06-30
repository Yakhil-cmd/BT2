### Title
Unchecked Precompile Call Return Value in `withdrawToNear`/`withdrawToEthereum` Causes Permanent Token Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToNear` and `withdrawToEthereum` by first burning the caller's ERC-20 tokens and then invoking the Aurora exit precompile via inline assembly. The return value of the low-level `call` is captured in a local variable `res` but is **never checked**. If the precompile call fails for any reason (invalid NEAR account ID, malformed input, etc.), the tokens are permanently destroyed on Aurora with no corresponding withdrawal on NEAR and no revert to protect the user.

---

### Finding Description

In `EvmErc20.sol` the `withdrawToNear` function executes as follows:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                        0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked — no `if iszero(res) { revert(0,0) }`
    }
}
``` [1](#0-0) 

The identical pattern appears in `withdrawToEthereum` and in both functions of `EvmErc20V2.sol`: [2](#0-1) [3](#0-2) [4](#0-3) 

The target address `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` is the `ExitToNear` precompile, and `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab` is `ExitToEthereum`. Both precompiles perform strict input validation. For the ERC-20 path (flag `0x01`), the precompile calls `parse_recipient`, which validates the recipient bytes as a NEAR account ID: [5](#0-4) 

If validation fails, the precompile returns `ExitError`, the EVM sets `res = 0`, and execution continues in the Solidity function — which has already burned the tokens. No promise is ever scheduled, so the `error_refund` callback path is never reached either: [6](#0-5) 

These contracts are the production ERC-20 mirror deployed by the engine for every bridged NEP-141 token: [7](#0-6) 

---

### Impact Explanation

Any user who calls `withdrawToNear` or `withdrawToEthereum` with a recipient that fails precompile validation (e.g., an invalid NEAR account ID, an account ID that is too long, contains illegal characters, or is empty) will have their ERC-20 tokens **permanently burned** on Aurora with no corresponding NEP-141 tokens released on NEAR. The tokens are irrecoverably lost. This constitutes a **permanent freezing/destruction of user funds** — a Critical-severity impact.

---

### Likelihood Explanation

The entry point is the public `withdrawToNear(bytes memory recipient, uint256 amount)` function, callable by any token holder. A user who mistypes a NEAR account ID, passes an empty byte array, or passes a string that violates NEAR account ID rules (e.g., uppercase letters, leading/trailing separators, length > 64) will silently lose their tokens. No special privilege is required. The likelihood is **medium**: the function is a core user-facing bridge exit path, and recipient validation errors are a realistic user mistake.

---

### Recommendation

Check the return value of the precompile `call` and revert on failure, so that the `_burn` is rolled back:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                    0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Apply the same fix to `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`.

---

### Proof of Concept

1. Alice holds 1000 `EvmErc20` tokens on Aurora (bridged from a NEP-141 token).
2. Alice calls `withdrawToNear("INVALID!!ACCOUNT", 1000)` — the recipient contains uppercase letters and `!`, which are illegal in NEAR account IDs.
3. `_burn(Alice, 1000)` executes — Alice's 1000 tokens are destroyed.
4. The `ExitToNear` precompile's `parse_recipient` rejects `"INVALID!!ACCOUNT"` and returns `ExitError::Other("ERR_INVALID_RECEIVER_ACCOUNT_ID")`.
5. The EVM sets `res = 0`; the Solidity assembly block does not check it.
6. `withdrawToNear` returns normally (no revert).
7. No NEAR promise is scheduled; no NEP-141 tokens are released; no refund callback fires.
8. Alice has permanently lost 1000 tokens with no recourse.

### Citations

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

**File:** engine/src/engine.rs (L1321-1337)
```rust
    #[cfg(feature = "error_refund")]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20V2.bin");
    #[cfg(not(feature = "error_refund"))]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20.bin");

    let erc20_admin_address = current_address(current_account_id);
    let erc20_metadata = erc20_metadata.unwrap_or_default();

    let deploy_args = ethabi::encode(&[
        ethabi::Token::String(erc20_metadata.name),
        ethabi::Token::String(erc20_metadata.symbol),
        ethabi::Token::Uint(erc20_metadata.decimals.into()),
        ethabi::Token::Address(erc20_admin_address.raw().0.into()),
    ]);

    [erc20_contract, deploy_args.as_slice()].concat()
}
```
