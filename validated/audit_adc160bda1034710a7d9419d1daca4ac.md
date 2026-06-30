### Title
Unchecked Precompile Call Return Value in `withdrawToNear`/`withdrawToEthereum` Causes Permanent Fund Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20` and `EvmErc20V2` bridge contracts burn the caller's ERC-20 tokens before calling the Aurora exit precompile via inline assembly. The return value of that `call` opcode is stored in `res` but never checked. If the precompile call fails for any reason, the burn is not reverted (it occurred in the outer call frame), the user's tokens are permanently destroyed, and no corresponding NEP-141 transfer is initiated on NEAR.

---

### Finding Description

In `EvmErc20.sol`, both `withdrawToNear` and `withdrawToEthereum` follow this pattern:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked — silent failure
    }
}
``` [1](#0-0) 

The identical pattern exists in `withdrawToEthereum` and in both functions of `EvmErc20V2`: [2](#0-1) [3](#0-2) [4](#0-3) 

The EVM `call` opcode creates a new sub-context. If the precompile returns an error (exit reason `ExitError`), only state changes *inside* that sub-context are reverted. The `_burn` executed in the outer frame is **not** reverted. The function then returns successfully to the caller with no indication of failure.

The `ExitToNear` precompile in Rust validates inputs and can legitimately fail: [5](#0-4) 

Failure conditions include: invalid/oversized recipient account ID, precompile called in static or delegate context, amount exceeding `u128::MAX`, or insufficient gas forwarded to the precompile.

---

### Impact Explanation

**Critical — Permanent freezing/loss of user funds.**

When the precompile call fails silently:
- The user's ERC-20 tokens are burned (supply reduced, balance zeroed).
- No `ft_transfer` or `ft_transfer_call` promise is ever scheduled on NEAR.
- The NEP-141 tokens remain locked in the Aurora engine contract with no recovery path.
- The user has lost their bridged assets permanently.

---

### Likelihood Explanation

**Medium.** The `recipient` parameter in `withdrawToNear` is arbitrary user-supplied bytes. A caller can supply a byte sequence that is syntactically accepted by Solidity (any `bytes`) but is rejected by the NEAR account ID validator inside the Rust precompile (e.g., a string containing uppercase letters, spaces, or exceeding 64 characters). The precompile enforces NEAR account ID rules that Solidity cannot enforce. Any such call burns the tokens and silently discards the exit request.

Additionally, if the precompile is paused or gas is insufficient, the same silent-burn outcome occurs for all users.

---

### Recommendation

Check the return value of every `call` to the exit precompile and revert on failure, so the `_burn` is also reverted:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Apply this fix to all four assembly blocks across `EvmErc20.sol` and `EvmErc20V2.sol`. This mirrors the `safeTransfer` pattern recommended in the external report: always verify the outcome of a critical token-movement call before allowing state changes to persist.

---

### Proof of Concept

1. Deploy `EvmErc20` for a NEP-141 token; bridge tokens to Aurora so a user holds ERC-20 balance.
2. Call `withdrawToNear` with a `recipient` that is invalid as a NEAR account ID (e.g., `"INVALID ACCOUNT"` — uppercase + space).
3. The `_burn` executes, reducing the caller's ERC-20 balance to zero.
4. The `call` to the `ExitToNear` precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` fails (the precompile rejects the account ID), returning `0`.
5. `res` is never checked; the function returns without reverting.
6. The caller's ERC-20 tokens are gone; no NEP-141 transfer was initiated; the NEP-141 balance in the Aurora contract is unchanged.
7. The user has permanently lost their bridged funds with no recovery mechanism. [6](#0-5)

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
