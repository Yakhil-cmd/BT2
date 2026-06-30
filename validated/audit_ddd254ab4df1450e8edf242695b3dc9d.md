### Title
Unchecked Low-Level Precompile Call Return Value Causes Permanent Token Loss on Withdrawal - (`etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20` and `EvmErc20V2` — the production ERC-20 bridge token contracts deployed on Aurora — burn the caller's tokens before making a low-level `call` to the `exitToNear` and `exitToEthereum` precompiles. The return value of that `call` is stored in a local assembly variable `res` but is **never checked**. If the precompile call fails for any reason, the ERC-20 tokens are permanently destroyed while the corresponding NEP-141 tokens are never transferred to the recipient, resulting in irreversible loss of user funds.

---

### Finding Description

In `EvmErc20.sol` and `EvmErc20V2.sol`, both `withdrawToNear` and `withdrawToEthereum` follow the same pattern:

1. Call `_burn(_msgSender(), amount)` — permanently destroys the caller's ERC-20 tokens.
2. Construct calldata for the Aurora precompile.
3. Execute a low-level `call` to the precompile address in inline assembly.
4. Store the success flag in `res` — **and then do nothing with it**.

`EvmErc20.sol`, `withdrawToNear` (lines 53–63):
```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is never checked — silent failure
    }
}
```

The identical unchecked pattern appears in:
- `EvmErc20.withdrawToEthereum` (line 74)
- `EvmErc20V2.withdrawToNear` (line 62)
- `EvmErc20V2.withdrawToEthereum` (line 75)

The `exitToNear` precompile (`engine-precompiles/src/native.rs`, `ExitToNear::run`) can return `Err(ExitError::OutOfGas)`, `Err(ExitError::Other(...))`, or other failure variants under multiple conditions (insufficient gas, missing storage keys, invalid input parsing). When a precompile returns an error, the EVM `call` opcode returns `0` in the success flag. Because the Solidity assembly block never inspects `res`, the outer function returns successfully regardless of whether the precompile succeeded.

The burn is irreversible. There is no refund path in these contracts.

---

### Impact Explanation

**Critical — Permanent freezing/loss of funds.**

When the precompile call fails silently:
- The caller's ERC-20 tokens are permanently burned (total supply decreases).
- No NEP-141 tokens are transferred to the NEAR recipient.
- No ETH/ERC-20 withdrawal event is processed on the bridge.
- The user has no recourse; the tokens are gone.

This is a direct, irreversible loss of user funds triggered by a normal user action (calling `withdrawToNear` or `withdrawToEthereum`).

---

### Likelihood Explanation

**Realistic.** The `exitToNear` precompile can fail in production under several conditions reachable by an unprivileged user:

1. **Out-of-gas**: A user submitting a transaction with insufficient gas causes the precompile to return `ExitError::OutOfGas`. The burn has already executed; the precompile call fails silently.
2. **Missing storage key**: If `EthConnectorStorageId::EthConnectorAccount` is not set (e.g., during a misconfigured deployment or after a storage migration), `get_eth_connector_contract_account` returns `Err`, causing the precompile to fail.
3. **Invalid recipient**: While the precompile validates the recipient, any future precompile change that introduces new failure modes would silently burn tokens in all existing deployed `EvmErc20` contracts.

The burn-before-call ordering means any precompile failure, however transient, results in permanent loss.

---

### Recommendation

Check the return value of the low-level `call` and revert if it fails. The fix must be applied to all four affected functions in both contracts:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Alternatively, restructure the functions to call the precompile **before** burning, and only burn if the precompile call succeeds. This eliminates the need to revert a state change after the fact.

---

### Proof of Concept

**Root cause — `EvmErc20.sol` lines 53–63:** [1](#0-0) 

**Same pattern in `EvmErc20.withdrawToEthereum`:** [2](#0-1) 

**Same pattern in `EvmErc20V2.withdrawToNear` and `withdrawToEthereum`:** [3](#0-2) 

**Precompile failure modes — `ExitToNear::run` can return `Err` on OOG or missing storage:** [4](#0-3) [5](#0-4) 

**Attacker entry path**: Any holder of a bridged ERC-20 token calls `withdrawToNear(recipient, amount)` or `withdrawToEthereum(recipient, amount)` on the deployed `EvmErc20` or `EvmErc20V2` contract. If the precompile call fails (e.g., OOG), `_burn` has already executed, tokens are permanently destroyed, and the function returns without reverting.

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

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-77)
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

**File:** engine-precompiles/src/native.rs (L311-319)
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
```

**File:** engine-precompiles/src/native.rs (L404-417)
```rust
        let required_gas = Self::required_gas(input)?;

        if let Some(target_gas) = target_gas
            && required_gas > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        // It's not allowed to call exit precompiles in static mode
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_near::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
        }
```
