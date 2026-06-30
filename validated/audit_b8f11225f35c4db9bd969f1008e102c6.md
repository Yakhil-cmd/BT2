### Title
Unchecked Precompile Call Return Value After `_burn` Causes Permanent Token Destruction - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToNear()` and `withdrawToEthereum()` by first burning the caller's ERC-20 tokens via `_burn()`, then invoking the Aurora exit precompile via inline assembly. The return value of the assembly `call()` is captured in `res` but **never checked**. If the precompile call fails (returns 0), the burn is already committed and irreversible, while no corresponding NEP-141 or ETH transfer is ever scheduled. The user's tokens are permanently destroyed with no recourse.

---

### Finding Description

In `EvmErc20.sol` and `EvmErc20V2.sol`, both `withdrawToNear` and `withdrawToEthereum` follow the same pattern:

1. `_burn(sender, amount)` — permanently destroys the caller's ERC-20 balance.
2. An inline assembly `call()` to the hardcoded exit precompile address is made.
3. The return value `res` is assigned but **never read or validated**.

`EvmErc20.sol` `withdrawToNear` (lines 53–63): [1](#0-0) 

`EvmErc20.sol` `withdrawToEthereum` (lines 65–76): [2](#0-1) 

`EvmErc20V2.sol` exhibits the identical pattern in both functions: [3](#0-2) 

In the EVM, a `call()` to a precompile that encounters an error returns `0` (failure) **without reverting the outer call frame**. Because the `_burn` precedes the assembly block and there is no `require(res != 0)` guard, a failed precompile call leaves the transaction in a state where tokens are destroyed but no cross-chain transfer is initiated.

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) returns `ExitError` in multiple reachable conditions — for example, when the recipient bytes do not parse as a valid NEAR `AccountId`, when the `apparent_value` is non-zero for an ERC-20 exit, or when the NEP-141 mapping for the ERC-20 address is not found: [4](#0-3) 

Any of these error paths causes the precompile `call()` to return `0`. Because `res` is never checked, the outer function returns successfully with the burn committed and no NEAR-side transfer scheduled.

---

### Impact Explanation

**Critical — Permanent destruction of user funds.**

When the precompile call fails silently:
- The caller's ERC-20 tokens are irreversibly burned from Aurora's EVM state.
- No `ft_transfer` or `withdraw` promise is ever scheduled on the NEAR side.
- The corresponding NEP-141 balance held by the Aurora contract is never released to the user.
- There is no recovery path: the ERC-20 supply is reduced, but the NEP-141 backing remains locked in the Aurora contract forever.

---

### Likelihood Explanation

**Medium-High.** The `recipient` parameter in `withdrawToNear` is a raw `bytes` value supplied entirely by the caller. A caller who passes bytes that do not form a valid NEAR `AccountId` (e.g., an empty byte string, bytes containing invalid characters, or a string exceeding the 64-character NEAR account ID limit) will trigger a precompile parse error. The precompile returns `0`, `res` is silently discarded, and the burn is finalized. No special privilege is required — any token holder can trigger this path by calling `withdrawToNear` with a malformed recipient.

---

### Recommendation

Add a `require` check on the assembly return value in both functions of both contracts, so that a failed precompile call reverts the entire transaction (including the `_burn`):

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures atomicity: either the burn and the cross-chain transfer both succeed, or neither does.

---

### Proof of Concept

1. User holds 100 units of an `EvmErc20`-based bridged token on Aurora.
2. User calls `withdrawToNear(bytes(""), 100)` — passing an empty byte string as the recipient.
3. `_burn(msg.sender, 100)` executes; user's ERC-20 balance drops to 0.
4. The assembly `call()` invokes the `ExitToNear` precompile with a zero-length recipient.
5. Inside `exit_erc20_token_to_near`, `parse_recipient` fails to parse a valid `AccountId` from empty bytes and returns `ExitError`.
6. The precompile call returns `0` to the EVM.
7. `res` is never checked; `withdrawToNear` returns successfully.
8. The user's 100 ERC-20 tokens are permanently destroyed. No NEP-141 tokens are ever transferred. The NEP-141 backing remains locked in the Aurora contract. [1](#0-0) [5](#0-4) [6](#0-5)

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

**File:** engine-precompiles/src/native.rs (L558-583)
```rust
fn exit_erc20_token_to_near<I: IO>(
    context: &Context,
    exit_params: &Erc20TokenParams,
    io: &I,
) -> Result<
    (
        AccountId,
        String,
        events::ExitToNear,
        String,
        Option<TransferNearArgs>,
    ),
    ExitError,
> {
    // In case of withdrawing ERC-20 tokens, the `apparent_value` should be zero. In opposite way
    // the funds will be locked in the address of the precompile without any possibility
    // to withdraw them in the future. So, in case if the `apparent_value` is not zero, the error
    // will be returned to prevent that.
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }

    let erc20_address = context.caller; // because ERC-20 contract calls the precompile.
    let nep141_account_id = get_nep141_from_erc20(erc20_address.as_bytes(), io)?;
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
