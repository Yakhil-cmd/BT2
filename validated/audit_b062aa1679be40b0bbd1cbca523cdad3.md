### Title
Unchecked Precompile Call Return Value in `withdrawToNear`/`withdrawToEthereum` Allows Token Burn Without Cross-Chain Transfer - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

`EvmErc20.sol` and `EvmErc20V2.sol` burn the caller's ERC-20 tokens before invoking the `ExitToNear` or `ExitToEthereum` precompile via a raw assembly `call`. The return value of that `call` is captured in a local variable `res` but is **never checked**. If the precompile call fails for any reason (empty or invalid NEAR recipient, paused precompile, out-of-gas), the burn is irreversible and the user receives nothing on the destination chain, resulting in permanent loss of funds.

---

### Finding Description

In both `EvmErc20.sol` and `EvmErc20V2.sol`, the `withdrawToNear` and `withdrawToEthereum` functions follow this pattern:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // <-- tokens destroyed here, irreversibly

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                        0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked
    }
}
``` [1](#0-0) 

The same unchecked pattern appears in `withdrawToEthereum`: [2](#0-1) 

And identically in `EvmErc20V2.sol`: [3](#0-2) 

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) validates the recipient via `parse_recipient` and returns `ExitError` for malformed or empty input, which causes the EVM `call` opcode to return `0`. Because `res` is never inspected, the outer Solidity function returns successfully even when the precompile has rejected the call. [4](#0-3) 

The `ExitToNearParams::try_from` parser requires a valid flag byte and a parseable recipient account ID. An empty `recipient` bytes array, or one containing an invalid NEAR account ID string, causes the precompile to return `ExitError::Other("ERR_MISSING_FLAG")` or a recipient parse error, making `call` return `0`. [5](#0-4) 

---

### Impact Explanation

**Critical — Permanent freezing / direct theft of user funds.**

`_burn` is called before the precompile invocation and is unconditional. Once tokens are burned they cannot be recovered: there is no refund path, no revert, and no re-mint. If the precompile call fails silently, the user's ERC-20 balance is permanently destroyed with no corresponding NEP-141 or Ethereum-side credit. The total supply on the EVM side decreases while the NEAR/Ethereum side receives nothing, constituting an irreversible loss of user funds.

---

### Likelihood Explanation

**Medium.** Any unprivileged EVM user who calls `withdrawToNear` with:
- an empty `recipient` bytes array (`""`),
- a `recipient` that is not a valid NEAR account ID (e.g., contains uppercase letters, exceeds 64 chars, or is otherwise malformed),
- or insufficient gas forwarded to the precompile,

will trigger the silent failure. This is a realistic mistake for users interacting directly with the contract ABI, or for integrating contracts that construct the recipient dynamically. No special privileges are required.

---

### Recommendation

1. **Short term:** Check the return value of the assembly `call` and revert if it is zero, so that the `_burn` is rolled back:
   ```solidity
   assembly {
       let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                       0, add(input, 32), input_size, 0, 32)
       if iszero(res) { revert(0, 0) }
   }
   ```
2. **Long term:** Validate `recipient.length > 0` and enforce NEAR account ID format constraints before burning, so invalid inputs are rejected before any state change occurs.

---

### Proof of Concept

1. Alice holds 1000 `EvmErc20` tokens.
2. Alice calls `withdrawToNear("", 1000)` (empty recipient).
3. `_burn(Alice, 1000)` executes — Alice's balance drops to 0, total supply decreases by 1000.
4. The assembly `call` to the `ExitToNear` precompile at `0xe921...` is made with a 1-byte input (`\x01` flag only, no recipient). The precompile's `try_from` parser returns `ExitError::Other("ERR_MISSING_FLAG")` or a recipient parse failure; the `call` returns `res = 0`.
5. `res` is never checked. The function returns without reverting.
6. Alice has permanently lost 1000 tokens. No NEP-141 tokens are minted on NEAR. The funds are gone. [1](#0-0) [5](#0-4)

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

**File:** engine-precompiles/src/native.rs (L727-775)
```rust
impl<'a> TryFrom<&'a [u8]> for ExitToNearParams<'a> {
    type Error = ExitError;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        // The first byte of the input is a flag, selecting the behavior to be triggered:
        // 0x00 -> Eth(base) token withdrawal
        // 0x01 -> ERC-20 token withdrawal
        let flag = input
            .first()
            .copied()
            .ok_or_else(|| ExitError::Other(Cow::from("ERR_MISSING_FLAG")))?;

        #[cfg(feature = "error_refund")]
        let (refund_address, input) = parse_input(input)?;
        #[cfg(not(feature = "error_refund"))]
        let input = parse_input(input)?;

        match flag {
            0x0 => {
                let Recipient {
                    receiver_account_id,
                    message,
                } = parse_recipient(input)?;

                Ok(Self::BaseToken(BaseTokenParams {
                    #[cfg(feature = "error_refund")]
                    refund_address,
                    receiver_account_id,
                    message,
                }))
            }
            0x1 => {
                let amount = parse_amount(&input[..32])?;
                let Recipient {
                    receiver_account_id,
                    message,
                } = parse_recipient(&input[32..])?;

                Ok(Self::Erc20TokenParams(Erc20TokenParams {
                    #[cfg(feature = "error_refund")]
                    refund_address,
                    receiver_account_id,
                    amount,
                    message,
                }))
            }
            _ => Err(ExitError::Other(Cow::from("ERR_INVALID_FLAG"))),
        }
    }
```
