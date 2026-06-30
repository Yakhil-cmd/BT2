### Title
ERC-20 Bridge Token Burn Before Precompile Return Value Check Causes Permanent Token Loss - (`etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.withdrawToNear`, `EvmErc20.withdrawToEthereum`, `EvmErc20V2.withdrawToNear`, and `EvmErc20V2.withdrawToEthereum` call `_burn` on the caller's balance **before** invoking the exit precompile via inline assembly. The return value of the `call()` opcode (`res`) is captured but **never checked**. If the precompile call fails for any reason, the EVM transaction does not revert, the user's ERC-20 tokens are permanently destroyed, and no NEP-141 tokens are transferred to the NEAR recipient.

---

### Finding Description

In `EvmErc20.sol`, both withdrawal functions follow this pattern:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is assigned but never read or checked
    }
}
``` [1](#0-0) [2](#0-1) 

The same pattern exists in `EvmErc20V2.sol`: [3](#0-2) [4](#0-3) 

The `ExitToNear` precompile's `run()` method returns `Err(ExitError::Other(...))` in multiple reachable conditions. When a precompile returns `ExitError` (non-fatal), the EVM translates this to the `call()` opcode returning `0`, but the **caller's execution frame is not reverted**. The `_burn` that already executed is permanent.

Conditions under which the precompile returns a non-fatal `ExitError` (causing `res == 0` with no revert):

1. **Invalid NEAR account ID in `recipient`**: `get_nep141_from_erc20` or `ExitToNearParams::try_from` fails to parse the recipient bytes as a valid NEAR `AccountId`, returning `ERR_TARGET_TOKEN_NOT_FOUND` or `ERR_INVALID_NEP141_ACCOUNT`. [5](#0-4) 

2. **ERC-20 not registered in the NEP-141 map**: Any contract implementing `IExit` whose address is not in `KeyPrefix::Erc20Nep141Map` storage will trigger `ERR_TARGET_TOKEN_NOT_FOUND`.

3. **ETH attached to an ERC-20 exit call**: `context.apparent_value != U256::zero()` triggers `ERR_ETH_ATTACHED_FOR_ERC20_EXIT`. [6](#0-5) 

The `ExitToEthereum` precompile has the same class of errors for the `0x1` (ERC-20) branch: [7](#0-6) 

The `error_refund` feature only handles the case where the **async NEAR-side promise** (`ft_transfer`) fails after the EVM transaction commits. It does not protect against the precompile failing **synchronously** before any promise is scheduled, because in that case no callback is ever registered. [8](#0-7) 

---

### Impact Explanation

**Critical — Permanent freezing of user funds.**

When the precompile call fails and `res` is not checked, `_burn` has already destroyed the caller's ERC-20 tokens. No NEP-141 tokens are transferred on the NEAR side. The user's bridged assets are permanently destroyed with no recourse. This is a direct, irreversible loss of user funds reachable by any token holder.

---

### Likelihood Explanation

**Medium.** The most realistic trigger is a user supplying an invalid NEAR account ID as the `recipient` argument to `withdrawToNear`. NEAR account IDs have strict validity rules (length, character set, subaccount depth). A user who mistypes or programmatically constructs an invalid account ID will silently lose their tokens. The `IExit` interface is public and imposes no validation on `recipient` before the burn. The `withdrawToEthereum` path is less likely to fail for registered tokens but is equally unprotected.

---

### Recommendation

Check the return value of the precompile `call()` and revert if it is zero:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    bool success;
    assembly {
        success := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    }
    require(success, "ERR_EXIT_TO_NEAR_FAILED");
}
```

Alternatively, validate the `recipient` as a valid NEAR account ID before burning, or restructure the call to invoke the precompile first and only burn on success (requires architectural changes since `_burn` is what signals the amount to the precompile).

---

### Proof of Concept

1. User holds 100 units of a bridged ERC-20 token (`EvmErc20` instance).
2. User calls `withdrawToNear(bytes("invalid account id!!"), 100)` where the recipient is not a valid NEAR account ID.
3. `_burn(msg.sender, 100)` executes — user's balance drops to 0.
4. The assembly `call` to `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` is made. The `ExitToNear` precompile's `run()` fails to parse the recipient as a valid `AccountId` and returns `Err(ExitError::Other("ERR_TARGET_TOKEN_NOT_FOUND"))` or a parse error.
5. The `call()` opcode returns `res = 0`. The assembly block exits. No `require` or check follows.
6. `withdrawToNear` returns normally. The EVM transaction succeeds.
7. The user's 100 ERC-20 tokens are permanently burned. No NEP-141 `ft_transfer` promise was ever scheduled. The user receives nothing. [1](#0-0) [9](#0-8) [5](#0-4)

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

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-63)
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

**File:** engine-precompiles/src/native.rs (L302-309)
```rust
fn get_nep141_from_erc20<I: IO>(erc20_token: &[u8], io: &I) -> Result<AccountId, ExitError> {
    AccountId::try_from(
        io.read_storage(bytes_to_key(KeyPrefix::Erc20Nep141Map, erc20_token).as_slice())
            .map(|s| s.to_vec())
            .ok_or(ExitError::Other(Cow::Borrowed(ERR_TARGET_TOKEN_NOT_FOUND)))?,
    )
    .map_err(|_| ExitError::Other(Cow::Borrowed("ERR_INVALID_NEP141_ACCOUNT")))
}
```

**File:** engine-precompiles/src/native.rs (L419-446)
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

**File:** engine-precompiles/src/native.rs (L576-580)
```rust
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }
```

**File:** engine-precompiles/src/native.rs (L926-930)
```rust
                if context.apparent_value != U256::from(0) {
                    return Err(ExitError::Other(Cow::from(
                        "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
                    )));
                }
```
