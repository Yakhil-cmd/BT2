### Title
`EvmErc20V2.withdrawToNear` Silently Burns User Tokens Due to Input Format Mismatch with `ExitToNear` Precompile When `error_refund` Feature Is Disabled — (`etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

`EvmErc20V2.withdrawToNear` first burns the caller's ERC-20 tokens, then calls the `ExitToNear` precompile with an input layout that embeds the sender address (20 bytes) between the flag byte and the amount. When the Aurora Engine binary is compiled **without** the `error_refund` feature, the precompile's parser does not account for those 20 bytes, misreads the amount field, and returns `ERR_INVALID_AMOUNT`. Because the Solidity assembly block never checks the call's return value, the outer transaction succeeds, the tokens are permanently burned, and no NEAR-side transfer is ever scheduled — a permanent fund freeze.

---

### Finding Description

**`EvmErc20V2.withdrawToNear` input layout** (V2-specific):

```
[0x01 | sender (20 B) | amount (32 B) | recipient (variable)]
``` [1](#0-0) 

**`ExitToNear` precompile — `parse_input` without `error_refund`:**

```rust
#[cfg(not(feature = "error_refund"))]
fn parse_input(input: &[u8]) -> Result<&[u8], ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    Ok(&input[1..])   // strips only the flag byte
}
``` [2](#0-1) 

After stripping the flag byte, the remaining slice is `[sender(20), amount(32), recipient]`. The flag-`0x01` branch then reads:

```rust
let amount = parse_amount(&input[..32])?;   // reads sender[0..20] + amount[0..12]
``` [3](#0-2) 

`parse_amount` rejects any value exceeding `u128::MAX`:

```rust
if amount > U256::from(u128::MAX) {
    return Err(ExitError::Other(Cow::from("ERR_INVALID_AMOUNT")));
}
``` [4](#0-3) 

For any non-zero sender address the high 20 bytes of the 32-byte "amount" field are non-zero, so the value always exceeds `u128::MAX`. The precompile returns an error, the EVM call returns `0`, but the Solidity assembly never checks `res`:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    // res is never inspected
}
``` [5](#0-4) 

The outer transaction succeeds. The tokens burned by `_burn(sender, amount)` are gone; no NEAR promise is ever created. [6](#0-5) 

By contrast, `EvmErc20` (V1) sends `[0x01 | amount(32) | recipient]`, which is correctly parsed by the precompile regardless of the `error_refund` flag. [7](#0-6) 

With `error_refund` **enabled**, `parse_input` strips 21 bytes (flag + 20-byte refund address), leaving `[amount(32) | recipient]` — the correct layout for V2. Without it, V2 is broken. [8](#0-7) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**  
Any user who calls `withdrawToNear` on an `EvmErc20V2`-deployed mirror token while the engine binary lacks the `error_refund` feature will have their ERC-20 tokens irreversibly burned with no corresponding NEP-141 credit on NEAR. The tokens cannot be recovered.

---

### Likelihood Explanation

`withdrawToNear` is the standard, publicly callable withdrawal path for every bridged NEP-141 token represented by an `EvmErc20V2` contract. Any token holder can trigger it. The failure is completely silent from the user's perspective (no revert, no error event), so victims may not discover the loss until they check their NEAR balance. The condition is met whenever `EvmErc20V2` contracts are live and the engine binary was compiled without `error_refund`.

---

### Recommendation

1. **Revert on precompile failure** inside `EvmErc20V2.withdrawToNear`:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures the `_burn` is rolled back if the precompile rejects the call, preventing silent token loss.

2. **Enforce feature parity**: document (or enforce at build time) that `EvmErc20V2` contracts must only be deployed against an engine binary compiled with `error_refund`.

3. **Audit all callers** of the `ExitToNear` precompile for unchecked return values.

---

### Proof of Concept

1. Engine compiled **without** `error_refund`.
2. A NEP-141 token is mirrored as `EvmErc20V2` on Aurora.
3. Alice holds 100 mirror tokens and calls `withdrawToNear("alice.near", 100e18)`.
4. `_burn(alice, 100e18)` executes — Alice's balance drops to 0.
5. Precompile input: `[0x01, alice_addr(20), 100e18(32), "alice.near"]`.
6. `parse_input` (no `error_refund`) strips only the flag → remaining = `[alice_addr(20), 100e18(32), "alice.near"]`.
7. `parse_amount(&input[..32])` reads `alice_addr[0..20] ++ 100e18[0..12]` — a value >> `u128::MAX`.
8. Precompile returns `ERR_INVALID_AMOUNT`; EVM call returns `res = 0`.
9. Assembly block ignores `res`; `withdrawToNear` returns normally.
10. Alice's 100 mirror tokens are gone; her NEAR account receives nothing.

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

**File:** engine-precompiles/src/native.rs (L337-344)
```rust
fn parse_amount(input: &[u8]) -> Result<U256, ExitError> {
    let amount = U256::from_big_endian(input);

    if amount > U256::from(u128::MAX) {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_AMOUNT")));
    }

    Ok(amount)
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
