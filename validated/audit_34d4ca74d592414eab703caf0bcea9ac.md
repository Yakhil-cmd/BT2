### Title
`EvmErc20V2.withdrawToNear` Sends Mismatched Input to `ExitToNear` Precompile, Causing Permanent ERC-20 Token Loss - (File: `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

`EvmErc20V2.withdrawToNear` encodes the caller's `sender` address (20 bytes) into the precompile input between the flag byte and the amount field. The `ExitToNear` precompile, when compiled **without** the `error_refund` feature, strips only the flag byte and then reads the first 32 bytes of the remaining input as the withdrawal amount. Those 32 bytes are `sender[0..20] | amount[0..12]`, not the actual amount. The precompile rejects this as `ERR_INVALID_AMOUNT` (because the value exceeds `u128::MAX`), but the `_burn` already executed and the assembly call's return value is never checked. The user's ERC-20 tokens are permanently destroyed with no corresponding NEP-141 transfer.

---

### Finding Description

**`EvmErc20V2.withdrawToNear` input layout (always):**

```solidity
// etc/eth-contracts/contracts/EvmErc20V2.sol  lines 53-63
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    address sender = _msgSender();
    _burn(sender, amount);                                          // ← burn is irreversible

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
    //                                    flag    20 B   32 B      N B
    uint input_size = 1 + 20 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is never checked; no revert on failure
    }
}
``` [1](#0-0) 

**`ExitToNear` precompile `parse_input` without `error_refund`:**

```rust
// engine-precompiles/src/native.rs  lines 787-791
#[cfg(not(feature = "error_refund"))]
fn parse_input(input: &[u8]) -> Result<&[u8], ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    Ok(&input[1..])   // strips only the flag byte
}
``` [2](#0-1) 

After `parse_input`, the remaining slice is `sender (20 B) | amount (32 B) | recipient`. The parser then reads the first 32 bytes as the amount:

```rust
// engine-precompiles/src/native.rs  lines 758-763
0x1 => {
    let amount = parse_amount(&input[..32])?;   // reads sender[0..20] | amount[0..12]
    let Recipient { .. } = parse_recipient(&input[32..])?;
    ...
}
``` [3](#0-2) 

`parse_amount` rejects any value exceeding `u128::MAX`:

```rust
// engine-precompiles/src/native.rs  lines 337-344
fn parse_amount(input: &[u8]) -> Result<U256, ExitError> {
    let amount = U256::from_big_endian(input);
    if amount > U256::from(u128::MAX) {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_AMOUNT")));
    }
    Ok(amount)
}
``` [4](#0-3) 

For any real Ethereum address, the first 16 bytes of the 32-byte parsed value are non-zero (they come from the sender address), so the parsed value always exceeds `u128::MAX`. The precompile returns `ERR_INVALID_AMOUNT`. The EVM `call` returns `res = 0`, but `EvmErc20V2.sol` never checks `res` and never reverts. The `_burn` that already executed is permanent.

**Contrast with `error_refund` path:**

```rust
// engine-precompiles/src/native.rs  lines 778-785
#[cfg(feature = "error_refund")]
fn parse_input(input: &[u8]) -> Result<(Address, &[u8]), ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    let mut buffer = [0; 20];
    buffer.copy_from_slice(&input[1..21]);
    let refund_address = Address::from_array(buffer);
    Ok((refund_address, &input[21..]))   // strips flag + 20-byte sender → amount is correct
}
``` [5](#0-4) 

With `error_refund`, the 20-byte sender is consumed as `refund_address`, leaving `amount (32 B) | recipient` — the correct layout. `EvmErc20V2` was designed for this feature, but the feature is conditional and not guaranteed to be active.

**`EvmErc20.sol` (V1) does not have this bug** — it omits the sender from the input:

```solidity
// etc/eth-contracts/contracts/EvmErc20.sol  lines 53-62
bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
``` [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

Every call to `EvmErc20V2.withdrawToNear` on a deployment compiled without `error_refund`:

1. Burns the caller's ERC-20 tokens (irreversible on-chain state change).
2. Calls the `ExitToNear` precompile with a malformed amount field.
3. The precompile fails with `ERR_INVALID_AMOUNT` for any realistic sender address.
4. No NEP-141 tokens are transferred to the NEAR recipient.
5. No refund occurs (no `error_refund` path, no Solidity revert).

The user's bridged tokens are permanently destroyed. The NEP-141 supply held by the Aurora contract is not reduced, creating a growing divergence between the ERC-20 supply and the NEP-141 backing — an insolvency analog to the report's bad-debt accumulation.

---

### Likelihood Explanation

Any unprivileged EVM user holding `EvmErc20V2` tokens and calling `withdrawToNear` triggers the loss. No special conditions are required beyond the deployment using `EvmErc20V2` without the `error_refund` feature. The `error_refund` feature is conditional (`#[cfg(feature = "error_refund")]`) and is not guaranteed to be active in all production builds, as evidenced by the dual-path test coverage:

```rust
// engine-tests/src/tests/erc20_connector.rs
#[cfg(feature = "error_refund")]
let balance = FT_TRANSFER_AMOUNT.into();
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [7](#0-6) 

---

### Recommendation

1. **In `EvmErc20V2.sol`**: Check the return value of the assembly `call` and revert if it fails, so the `_burn` is rolled back on precompile failure:
   ```solidity
   assembly {
       let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
       if iszero(res) { revert(0, 0) }
   }
   ```
2. **In `ExitToNear` precompile**: When `error_refund` is disabled, document and enforce that the V2 input format (with sender prefix) is not accepted, or add a feature-agnostic path that correctly handles both input layouts.
3. **Deployment gate**: Ensure `EvmErc20V2` is only deployed alongside WASM compiled with `error_refund` enabled, or replace it with a version that does not embed the sender in the precompile input when refund is unavailable.

---

### Proof of Concept

**Setup**: Deploy Aurora without `error_refund` feature. Deploy a NEP-141 token, bridge it to Aurora (creating an `EvmErc20V2` mirror), and fund a user with ERC-20 tokens.

**Attack**:
```solidity
// User calls withdrawToNear with 100 tokens to "alice.near"
evmErc20V2.withdrawToNear("alice.near", 100e18);
```

**Trace**:
1. `_burn(user, 100e18)` executes — user's ERC-20 balance drops to 0.
2. Precompile input: `0x01 | user_address (20 B) | 100e18 (32 B) | "alice.near"`
3. `parse_input` (no `error_refund`) strips only `0x01`, leaving `user_address | 100e18 | "alice.near"`.
4. `parse_amount(&input[..32])` reads `user_address[0..20] | 100e18[0..12]` as a U256 ≫ `u128::MAX`.
5. Precompile returns `Err(ExitError::Other("ERR_INVALID_AMOUNT"))`.
6. EVM `call` returns `res = 0`; `EvmErc20V2` does not revert.
7. Transaction succeeds. User has 0 ERC-20 tokens. "alice.near" receives 0 NEP-141 tokens.
8. Tokens are permanently lost.

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

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-62)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
```

**File:** engine-tests/src/tests/erc20_connector.rs (L656-660)
```rust
        #[cfg(feature = "error_refund")]
        let balance = FT_TRANSFER_AMOUNT.into();
        // If the refund feature is not enabled then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
```
