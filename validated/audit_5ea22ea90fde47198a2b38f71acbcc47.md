### Title
`EvmErc20V2.withdrawToNear` Input Encoding Mismatch with `ExitToNear` Precompile Causes Permanent Token Loss — (`etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

`EvmErc20V2.sol`'s `withdrawToNear` function encodes a 20-byte `sender` address into the precompile calldata between the flag byte and the amount field. The `ExitToNear` precompile compiled **without** the `error_refund` feature does not expect this extra field. The precompile reads `sender[0..20] ++ amount[0..12]` as the 32-byte amount, producing a value that always exceeds `u128::MAX`, causing the precompile to revert with `ERR_INVALID_AMOUNT`. Because tokens are burned before the precompile call and the assembly return value is never checked, the EVM transaction succeeds while the user's tokens are permanently destroyed.

---

### Finding Description

**`EvmErc20V2.sol` `withdrawToNear` calldata layout:**

```solidity
// etc/eth-contracts/contracts/EvmErc20V2.sol  lines 53-63
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    address sender = _msgSender();
    _burn(sender, amount);                                          // ← tokens burned first

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
    //                                    flag(1)  addr(20) amt(32)  recip(var)
    uint input_size = 1 + 20 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                        0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked
    }
}
``` [1](#0-0) 

**`ExitToNear` precompile parsing (without `error_refund`):**

```rust
// engine-precompiles/src/native.rs  lines 787-791
#[cfg(not(feature = "error_refund"))]
fn parse_input(input: &[u8]) -> Result<&[u8], ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    Ok(&input[1..])   // strips only the 1-byte flag; no 20-byte address consumed
}
``` [2](#0-1) 

After `parse_input`, the remaining slice for flag `0x1` (ERC-20) is:

```
sender[0..20] ++ amount_b[0..12] ++ amount_b[12..32] ++ recipient
```

The precompile then calls:

```rust
// engine-precompiles/src/native.rs  lines 758-763
0x1 => {
    let amount = parse_amount(&input[..32])?;   // reads sender[0..20] ++ amount_b[0..12]
    ...
}
``` [3](#0-2) 

`parse_amount` rejects any value exceeding `u128::MAX`:

```rust
// engine-precompiles/src/native.rs  lines 337-345
fn parse_amount(input: &[u8]) -> Result<U256, ExitError> {
    let amount = U256::from_big_endian(input);
    if amount > U256::from(u128::MAX) {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_AMOUNT")));
    }
    Ok(amount)
}
```

<cite repo="Jortegata/aurora-engine--020" path="engine-precompiles/src/native.rs"

### Citations

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

**File:** engine-precompiles/src/native.rs (L758-763)
```rust
            0x1 => {
                let amount = parse_amount(&input[..32])?;
                let Recipient {
                    receiver_account_id,
                    message,
                } = parse_recipient(&input[32..])?;
```

**File:** engine-precompiles/src/native.rs (L787-791)
```rust
#[cfg(not(feature = "error_refund"))]
fn parse_input(input: &[u8]) -> Result<&[u8], ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    Ok(&input[1..])
}
```
