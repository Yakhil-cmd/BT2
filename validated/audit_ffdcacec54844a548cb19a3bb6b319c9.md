### Title
Unchecked Precompile Call Return Value in `withdrawToNear`/`withdrawToEthereum` Causes Permanent Token Burn Without NEAR-Side Release - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToNear` and `withdrawToEthereum` by first burning the caller's ERC-20 tokens via `_burn`, then calling the Aurora exit precompile via inline assembly. The assembly `call` return value (`res`) is assigned but **never checked**. If the precompile call fails for any reason (e.g., the precompile is paused, out of gas, or the ERC-20 is not registered in the NEP-141 map), the burn is committed but no corresponding NEP-141 tokens are released on NEAR or Ethereum. The user's tokens are permanently destroyed.

---

### Finding Description

In `EvmErc20.sol` and `EvmErc20V2.sol`, the withdrawal functions follow this pattern:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);   // ← tokens destroyed here, irreversibly

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked — no require(res != 0)
    }
}
``` [1](#0-0) 

The same pattern appears in `withdrawToEthereum` (calling `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`) and in both functions of `EvmErc20V2.sol`: [2](#0-1) [3](#0-2) [4](#0-3) 

The precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` is `ExitToNear`, implemented in `engine-precompiles/src/native.rs`. It can fail and return 0 to the EVM `call` instruction under multiple conditions:

**1. Precompile is paused.** The `Precompiles::execute` dispatcher checks `is_paused` before dispatching and returns `PrecompileFailure::Fatal` if paused. In the EVM, a fatal precompile failure causes the `call` opcode to return 0: [5](#0-4) 

**2. Out of gas.** If the caller forwards insufficient gas, `ExitToNear::run` returns `Err(ExitError::OutOfGas)`: [6](#0-5) 

**3. ERC-20 not registered.** If the calling ERC-20 contract address has no NEP-141 mapping in storage, `get_nep141_from_erc20` returns `ERR_TARGET_TOKEN_NOT_FOUND`: [7](#0-6) 

**4. Eth connector account not found.** If the connector storage key is missing, `get_eth_connector_contract_account` returns `ERR_KEY_NOT_FOUND`: [8](#0-7) 

In all these cases, the EVM `call` instruction returns `res = 0`. Because the Solidity code never executes `require(res != 0)`, the transaction does not revert. The `_burn` that already executed is committed. The user's ERC-20 tokens are gone, and no NEAR-side `ft_transfer` promise is ever created.

This is structurally identical to the RealityCards H-01 bug: an operation whose return value signals failure is not checked, so accounting (here: the burn) is applied even when the downstream action (here: the precompile call) fails.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

When the precompile call fails silently:
- The user's ERC-20 mirror tokens are burned (supply reduced).
- No NEP-141 `ft_transfer` promise is scheduled on NEAR.
- The underlying NEP-141 tokens remain locked in the Aurora engine contract with no recovery path for the user.
- There is no refund mechanism in the Solidity contract (no `try/catch`, no `require`).

The `error_refund` feature in the Rust precompile handles the case where the NEAR-side promise fails *after* the precompile succeeds — it does not protect against the precompile call itself returning 0 to the Solidity caller. [9](#0-8) 

---

### Likelihood Explanation

**High.** The most realistic trigger is a pause of the `ExitToNear` or `ExitToEthereum` precompile. Pausing is a documented operational action (the `PausePrecompiles` method exists and is tested). Any user who calls `withdrawToNear` or `withdrawToEthereum` during a pause window will permanently lose their tokens. The user has no way to know the precompile is paused before submitting the transaction, and no way to recover after. Additionally, the out-of-gas path is reachable by any caller who forwards insufficient gas to the assembly `call`.

---

### Recommendation

Add a return-value check immediately after each assembly block in both `EvmErc20.sol` and `EvmErc20V2.sol`:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures that if the precompile call fails for any reason, the entire transaction reverts — including the `_burn` — so no tokens are lost. Apply the same fix to `withdrawToEthereum` in both contracts.

---

### Proof of Concept

1. Deploy `EvmErc20` (or `EvmErc20V2`) as a bridged ERC-20 mirror on Aurora.
2. Mint tokens to `alice` via `mint(alice, 1000)`.
3. Admin calls `PausePrecompiles` to pause the `ExitToNear` precompile (`0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`).
4. `alice` calls `withdrawToNear("alice.near", 500)`.
5. `_burn(alice, 500)` executes — alice's ERC-20 balance drops from 1000 to 500.
6. The assembly `call` to the paused precompile returns `res = 0` (the precompile dispatcher returns `PrecompileFailure::Fatal` per `engine-precompiles/src/lib.rs:140-143`).
7. `res` is never checked — no revert occurs.
8. Transaction succeeds. Alice's 500 tokens are burned. No `ft_transfer` promise is created on NEAR. The 500 NEP-141 tokens remain locked in the Aurora engine contract permanently. [5](#0-4) [1](#0-0)

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

**File:** engine-precompiles/src/lib.rs (L140-144)
```rust
        if self.is_paused(&address) {
            return Some(Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
            }));
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

**File:** engine-precompiles/src/native.rs (L311-320)
```rust
fn get_eth_connector_contract_account<I: IO>(io: &I) -> Result<AccountId, ExitError> {
    io.read_storage(&construct_contract_key(
        EthConnectorStorageId::EthConnectorAccount,
    ))
    .ok_or(ExitError::Other(Cow::Borrowed("ERR_KEY_NOT_FOUND")))
    .and_then(|x| {
        x.to_value()
            .map_err(|_| ExitError::Other(Cow::Borrowed("ERR_DESERIALIZE")))
    })
}
```

**File:** engine-precompiles/src/native.rs (L406-410)
```rust
        if let Some(target_gas) = target_gas
            && required_gas > target_gas
        {
            return Err(ExitError::OutOfGas);
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
