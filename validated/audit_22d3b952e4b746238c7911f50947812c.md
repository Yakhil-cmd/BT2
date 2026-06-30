### Title
Unchecked Return Value of Exit Precompile `call` Leads to Permanent Token Burn Without Cross-Chain Transfer - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

### Summary
Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToNear` and `withdrawToEthereum` by first burning the caller's tokens via `_burn()`, then invoking the exit precompile via inline assembly. The return value `res` of the low-level `call` opcode is captured but never checked. If the precompile call fails (returns `0`), the transaction does not revert, the tokens are permanently destroyed, and no corresponding cross-chain transfer is initiated.

### Finding Description
In `withdrawToNear` and `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`, the pattern is:

1. `_burn(sender, amount)` — irreversibly destroys the caller's ERC-20 tokens.
2. An inline assembly block calls the exit precompile at a hardcoded address.
3. The result `res` of the `call` opcode is stored in a local assembly variable but **never tested**. No `if iszero(res) { revert(0,0) }` guard exists.

```solidity
// EvmErc20.sol, withdrawToNear, lines 60-62
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    // res is never checked
}
```

The same pattern appears in `withdrawToEthereum` (lines 73-75 of `EvmErc20.sol`) and in both functions of `EvmErc20V2.sol` (lines 61-63 and 74-76). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation
If the precompile call returns `0` (failure), execution continues normally after the assembly block. The `_burn` has already executed and is not rolled back. The user's ERC-20 tokens are permanently destroyed with no corresponding NEAR or Ethereum tokens minted on the destination chain. This constitutes **permanent freezing/destruction of user funds** — a Critical impact.

### Likelihood Explanation
Any token holder can call `withdrawToNear` or `withdrawToEthereum` directly. The precompile call can fail due to: malformed recipient bytes, out-of-gas conditions inside the precompile, or any internal precompile error state. Because the burn precedes the call and no revert guard exists, any such failure silently destroys the user's tokens. The entry path is fully unprivileged and reachable by any EVM user holding bridged ERC-20 tokens.

### Recommendation
Add a revert guard inside the assembly block to ensure the transaction reverts if the precompile call fails:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Apply this fix to both `withdrawToNear` and `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`.

### Proof of Concept

1. User holds 100 units of a bridged ERC-20 token deployed as `EvmErc20` or `EvmErc20V2`.
2. User calls `withdrawToNear(recipient_bytes, 100)`.
3. `_burn(msg.sender, 100)` executes — user's balance drops to 0.
4. The assembly `call` to the exit precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` fails (returns `0`) due to, e.g., an out-of-gas condition or malformed `recipient` encoding.
5. `res == 0` is never checked; execution falls through the assembly block.
6. The function returns successfully. No NEAR-side `ft_transfer` is triggered.
7. The user has lost 100 tokens permanently — burned on Aurora, never minted on NEAR. [1](#0-0) [3](#0-2)

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
