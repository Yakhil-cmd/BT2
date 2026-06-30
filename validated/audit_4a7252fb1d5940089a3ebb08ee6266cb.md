### Title
Unchecked Precompile `call()` Return Value in `withdrawToNear` and `withdrawToEthereum` Causes Permanent Token Loss — (`etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToNear()` and `withdrawToEthereum()` by first burning the caller's ERC-20 tokens via `_burn()`, then invoking the Aurora exit precompile via inline assembly `call()`. The return value `res` of that `call()` is captured but never checked. If the precompile call fails for any reason, the burn is not reverted, and the user's tokens are permanently destroyed with no corresponding release of funds on the NEAR or Ethereum side.

---

### Finding Description

In `EvmErc20.sol`, `withdrawToNear` and `withdrawToEthereum` follow this pattern:

```solidity
// EvmErc20.sol lines 53–76
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // tokens destroyed here — irreversible

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked — no `if iszero(res) { revert(0,0) }`
    }
}
```

The identical pattern appears in `withdrawToEthereum` (lines 65–76 of `EvmErc20.sol`) and in both functions of `EvmErc20V2.sol` (lines 53–77).

The Aurora-specific precompiles at these addresses (`exitToNear` = `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`, `exitToEthereum` = `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`) can and do return failure (EVM `call()` returns 0) under several conditions validated in `engine-precompiles/src/native.rs`:

- `validate_input_size` rejects inputs outside the allowed byte range.
- `parse_recipient` rejects malformed or invalid NEAR account IDs.
- `parse_amount` rejects amounts exceeding `u128::MAX`.
- Various serialization or state-read errors also cause the precompile to return `ExitError`.

Because `res` is never tested, the EVM `call()` failure is silently swallowed. The `_burn()` that preceded it is not rolled back (it is a state change already committed within the same call frame), so the user's ERC-20 balance is permanently zeroed with no corresponding NEP-141 transfer or Ethereum withdrawal ever scheduled. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

**Critical — Permanent freezing/destruction of user funds.**

When the precompile call fails silently:
- The ERC-20 tokens are burned and gone from the Aurora EVM state.
- No NEAR-side `ft_transfer` / `withdraw` promise is ever created (the precompile only schedules the promise on success).
- No Ethereum-side withdrawal is initiated.

The user loses the full `amount` of bridged tokens with no recovery path. This is a direct, irreversible loss of principal, not merely unclaimed yield. [5](#0-4) 

---

### Likelihood Explanation

**High.** The `recipient` argument of `withdrawToNear` is a raw `bytes` value supplied entirely by the caller. The `exitToNear` precompile parses it as a NEAR account ID and rejects it with an `ExitError` if it is invalid (e.g., contains illegal characters, exceeds the 64-byte NEAR account ID limit, or is empty). A user who passes a malformed recipient — whether by mistake or due to a front-end bug — will silently lose their tokens. No special privilege is required; any ERC-20 token holder can trigger this path. [6](#0-5) 

---

### Recommendation

After the assembly `call()`, check `res` and revert if it is zero:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Apply this fix to **all four** assembly blocks:
- `EvmErc20.withdrawToNear` (line 61)
- `EvmErc20.withdrawToEthereum` (line 74)
- `EvmErc20V2.withdrawToNear` (line 62)
- `EvmErc20V2.withdrawToEthereum` (line 75)

This ensures that if the precompile rejects the call for any reason, the entire transaction reverts, the `_burn()` is rolled back, and the user retains their tokens. [7](#0-6) [8](#0-7) 

---

### Proof of Concept

1. User holds 100 units of a bridged NEP-141 token represented as `EvmErc20` on Aurora.
2. User calls `withdrawToNear(bytes("invalid account id!!!"), 100)`.
3. `_burn(msg.sender, 100)` executes — user's ERC-20 balance drops to 0.
4. The assembly `call()` invokes the `exitToNear` precompile with the malformed recipient.
5. The precompile's `parse_recipient` (via `AccountId` validation) returns `ExitError` → the EVM `call()` returns `res = 0`.
6. Since `res` is never checked, execution continues normally and the function returns without reverting.
7. User's 100 ERC-20 tokens are permanently burned; no NEP-141 transfer is scheduled on NEAR.
8. Funds are irrecoverably lost. [1](#0-0) [9](#0-8)

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

**File:** engine-precompiles/src/native.rs (L844-856)
```rust
impl<I: IO> Precompile for ExitToEthereum<I> {
    fn required_gas(_input: &[u8]) -> Result<EthGas, ExitError> {
        Ok(costs::EXIT_TO_ETHEREUM_GAS)
    }

    #[allow(clippy::too_many_lines)]
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        context: &Context,
        is_static: bool,
    ) -> EvmPrecompileResult {
```
