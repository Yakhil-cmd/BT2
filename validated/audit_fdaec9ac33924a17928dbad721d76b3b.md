### Title
`EvmErc20V2.withdrawToNear` Permanently Burns User Tokens When `error_refund` Feature Is Disabled - (File: `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

`EvmErc20V2.sol` encodes the caller's `sender` address (20 bytes) into the precompile calldata between the flag byte and the amount field. This layout is only correct when the Rust `error_refund` compile-time feature is active. When `error_refund` is **not** compiled in, the `ExitToNear` precompile's `parse_input` does not consume those 20 bytes, causing the amount field to be parsed as `[sender_address(20 bytes) || amount_high_12_bytes(12 bytes)]`. This value always exceeds `u128::MAX`, so `parse_amount` returns `ERR_INVALID_AMOUNT`. Because the Solidity assembly block does not check the call return value, the transaction succeeds while the user's ERC-20 tokens are permanently burned with no corresponding NEP-141 transfer.

---

### Finding Description

**`EvmErc20V2.sol` calldata layout (always):**

```
[0x01 flag (1)] [sender address (20)] [amount (32)] [recipient (variable)]
``` [1](#0-0) 

**`EvmErc20.sol` calldata layout (original, no sender field):**

```
[0x01 flag (1)] [amount (32)] [recipient (variable)]
``` [2](#0-1) 

The `ExitToNear` precompile has two compile-time variants of `parse_input`:

**With `error_refund`** — skips flag + 20 bytes (reads sender as `refund_address`):
```rust
Ok((refund_address, &input[21..]))
``` [3](#0-2) 

**Without `error_refund`** — skips only the flag byte:
```rust
Ok(&input[1..])
``` [4](#0-3) 

When `error_refund` is **not** enabled, the remaining slice after `parse_input` is:
```
[sender_address(20)] [amount(32)] [recipient(variable)]
```

The ERC-20 branch then reads the amount as:
```rust
let amount = parse_amount(&input[..32])?;
``` [5](#0-4) 

This reads `[sender_address(20 bytes) || amount_high_12_bytes(12 bytes)]` as a U256. Since any non-zero Ethereum address occupies the high 20 bytes of the 32-byte word, the resulting value is always far above `u128::MAX`. The guard in `parse_amount` then rejects it:

```rust
if amount > U256::from(u128::MAX) {
    return Err(ExitError::Other(Cow::from("ERR_INVALID_AMOUNT")));
}
``` [6](#0-5) 

The precompile call returns failure. However, `EvmErc20V2.withdrawToNear` does not check the assembly call result:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
}
``` [7](#0-6) 

The `_burn` executed before the call is not reverted. The user's ERC-20 tokens are permanently destroyed with no NEP-141 tokens ever transferred.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

Any user who calls `withdrawToNear` on a deployed `EvmErc20V2` instance when the engine is compiled without the `error_refund` feature will have their ERC-20 tokens burned and receive nothing in return. The NEP-141 tokens held by Aurora on behalf of that ERC-20 remain locked in Aurora's account with no mechanism to recover them, since the on-chain ERC-20 supply has already been reduced.

---

### Likelihood Explanation

`EvmErc20V2.sol` is a production contract in the repository. The `error_refund` flag is a Rust compile-time feature, meaning any deployment that omits it silently activates the broken parsing path. Every call to `withdrawToNear` on such a deployment results in total loss of the withdrawn amount. No special attacker capability is required — any token holder calling the standard bridge exit function is affected.

---

### Recommendation

1. **In `EvmErc20V2.sol`**: Check the return value of the assembly `call` and revert if it is zero, so the `_burn` is rolled back on precompile failure:
   ```solidity
   assembly {
       let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
       if iszero(res) { revert(0, 0) }
   }
   ```
2. **In `native.rs`**: Add a compile-time or runtime assertion that rejects `EvmErc20V2`-formatted input (21-byte prefix) when `error_refund` is disabled, rather than silently misinterpreting it.
3. **Deployment gate**: Ensure `EvmErc20V2` is only deployed when the engine binary is compiled with `error_refund` enabled, or document and enforce this constraint explicitly.

---

### Proof of Concept

1. Deploy Aurora engine **without** the `error_refund` Rust feature.
2. Bridge a NEP-141 token; Aurora deploys an `EvmErc20V2` instance for it.
3. User holds 1000 units of the ERC-20 on Aurora.
4. User calls `erc20.withdrawToNear("user.near", 1000)`.
5. `_burn(user, 1000)` executes — ERC-20 balance drops to 0.
6. Precompile receives `[0x01][user_addr(20)][1000_as_bytes32(32)]["user.near"]`.
7. `parse_input` (no `error_refund`) returns `[user_addr(20)][1000_as_bytes32(32)]["user.near"]`.
8. `parse_amount` reads `[user_addr(20)][1000_high_12_bytes(12)]` → value >> `u128::MAX` → `ERR_INVALID_AMOUNT`.
9. Precompile call returns 0; assembly ignores it; transaction succeeds.
10. User's ERC-20 balance: 0. NEP-141 balance: unchanged (still held by Aurora). Funds permanently lost. [1](#0-0) [8](#0-7) [4](#0-3)

### Citations

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

**File:** engine-precompiles/src/native.rs (L337-344)
```rust
fn parse_amount(input: &[u8]) -> Result<U256, ExitError> {
    let amount = U256::from_big_endian(input);

    if amount > U256::from(u128::MAX) {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_AMOUNT")));
    }

    Ok(amount)
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

**File:** engine-precompiles/src/native.rs (L778-785)
```rust
#[cfg(feature = "error_refund")]
fn parse_input(input: &[u8]) -> Result<(Address, &[u8]), ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    let mut buffer = [0; 20];
    buffer.copy_from_slice(&input[1..21]);
    let refund_address = Address::from_array(buffer);
    Ok((refund_address, &input[21..]))
}
```

**File:** engine-precompiles/src/native.rs (L787-791)
```rust
#[cfg(not(feature = "error_refund"))]
fn parse_input(input: &[u8]) -> Result<&[u8], ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    Ok(&input[1..])
}
```
