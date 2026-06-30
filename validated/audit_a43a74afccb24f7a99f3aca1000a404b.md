### Title
Unchecked Precompile Call Return Value After Token Burn Causes Permanent Fund Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

### Summary
In both `EvmErc20.sol` and `EvmErc20V2.sol`, the `withdrawToNear` and `withdrawToEthereum` functions burn the caller's ERC-20 tokens first, then invoke the Aurora exit precompile via a low-level assembly `call`. The return value of that assembly `call` is captured in `res` but **never checked**. If the precompile call fails for any reason, the tokens are permanently destroyed with no cross-chain release, resulting in irreversible fund loss.

### Finding Description
Both `withdrawToNear` and `withdrawToEthereum` in `EvmErc20` and `EvmErc20V2` follow this pattern:

```solidity
_burn(_msgSender(), amount);   // tokens destroyed unconditionally

assembly {
    let res := call(gas(), <precompile_address>, 0, add(input, 32), input_size, 0, 32)
    // res is NEVER checked — if call returns 0 (failure), execution continues silently
}
```

The `_burn` is irreversible. If the subsequent precompile `call` returns `0` (failure), the EVM transaction still succeeds from the Solidity perspective — no revert is triggered — so the user's tokens are gone and no cross-chain transfer is initiated.

Conditions under which the precompile call can fail and return `0`:
- **`withdrawToNear`**: The `recipient` parameter is a raw `bytes` value supplied by the caller. If it encodes an invalid or non-existent NEAR account ID, the `ExitToNear` precompile returns an error. The precompile validates the account ID format; a malformed byte string causes it to return `ExitError`, which the EVM translates to a `call` return value of `0`.
- **`withdrawToEthereum`**: Similarly, if the `ExitToEthereum` precompile encounters an error (e.g., the eth-connector is not configured, or the input is malformed), it returns `0`.
- **Out-of-gas in the precompile**: If insufficient gas is forwarded to the precompile, it returns `0`.

In all these cases, `_burn` has already executed and the tokens are gone. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation
**Critical — Permanent freezing/destruction of user funds.**

When the precompile call fails silently:
- The user's ERC-20 mirror tokens on Aurora are permanently burned (destroyed).
- No NEP-141 tokens are released on NEAR (for `withdrawToNear`), and no ETH is released on Ethereum (for `withdrawToEthereum`).
- There is no recovery mechanism: the burn is final, and the cross-chain accounting is never updated.
- The total supply of the ERC-20 mirror token decreases, but the backing NEP-141 supply on NEAR does not — creating a permanent accounting divergence (insolvency of the bridge peg).

### Likelihood Explanation
**Medium.** The most realistic trigger is a user calling `withdrawToNear` with a malformed `recipient` bytes argument (e.g., an empty byte array, a string exceeding NEAR account ID length limits, or bytes that do not form a valid NEAR account ID). This is an entirely unprivileged, user-controlled call path. No special permissions are required. Any EVM user holding mirror tokens can trigger this. The `recipient` field is not validated in Solidity before the burn, making accidental or adversarial misuse straightforward.

### Recommendation
Check the return value of the assembly `call` and revert if it is `0`. The burn must only be committed if the precompile call succeeds:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    uint256 res;
    assembly {
        res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    }
    require(res == 1, "ExitToNear precompile call failed");

    _burn(_msgSender(), amount); // burn AFTER confirming precompile success
}
```

Apply the same pattern to `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`. Alternatively, move the `_burn` after the assembly block and revert on failure, or restructure to use a checks-effects-interactions pattern where the precompile is called first and the burn only executes on confirmed success.

### Proof of Concept
1. Deploy `EvmErc20` (or `EvmErc20V2`) as a mirror of some NEP-141 token on Aurora.
2. Mint `1000` tokens to `attacker` address via `mint(attacker, 1000)`.
3. Call `withdrawToNear(bytes("!!invalid-near-account!!"), 1000)` from `attacker`.
   - `_burn(attacker, 1000)` executes: attacker's balance goes to `0`, total supply decreases by `1000`.
   - The assembly `call` to the `ExitToNear` precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` fails because `"!!invalid-near-account!!"` is not a valid NEAR account ID. The precompile returns `ExitError`, so `res = 0`.
   - No revert is triggered. The transaction succeeds.
4. Observe: attacker's ERC-20 balance is `0`, but no NEP-141 tokens were transferred on NEAR. The `1000` tokens are permanently destroyed with no cross-chain counterpart released. [1](#0-0) [3](#0-2)

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
