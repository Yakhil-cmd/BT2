Now I have all the information needed to analyze this claim precisely. Let me trace through the exact byte layouts.

### Title
EvmErc20V2.withdrawToNear Permanently Burns Tokens When Engine Compiled Without `error_refund` Feature — (`etc/eth-contracts/contracts/EvmErc20V2.sol` / `engine-precompiles/src/native.rs`)

---

### Summary

`EvmErc20V2.withdrawToNear` packs a 20-byte `sender` address between the flag byte and the amount field. When the engine is compiled without the `error_refund` feature, `parse_input` strips only the flag byte, causing `parse_amount` to read `sender[0..20] | amount[0..12]` as the 256-bit amount. This always exceeds `u128::MAX` for any non-zero sender, returning `ERR_INVALID_AMOUNT`. The precompile call fails, but the Solidity assembly block ignores the return value. Since `_burn` already executed, the user's tokens are permanently destroyed with no corresponding NEP-141 transfer.

---

### Finding Description

**Input layout mismatch between V2 contract and non-`error_refund` parser:**

`EvmErc20V2.withdrawToNear` constructs its precompile input as:

```
[0x01][sender: 20 bytes][amount_b: 32 bytes][recipient: N bytes]
``` [1](#0-0) 

The V1 contract (`EvmErc20.sol`) uses the legacy layout without the sender field:

```
[0x01][amount_b: 32 bytes][recipient: N bytes]
``` [2](#0-1) 

The precompile has two compile-time `parse_input` variants. **With** `error_refund`, it strips `flag(1) + refund_address(20)` = 21 bytes, correctly leaving `amount_b(32) | recipient`. **Without** `error_refund`, it strips only the flag byte (1 byte): [3](#0-2) 

This leaves `sender(20) | amount_b(32) | recipient` as the remaining slice. The ERC-20 branch then calls: [4](#0-3) 

`input[..32]` is now `sender[0..20] | amount_b[0..12]` — a 256-bit big-endian integer whose top 160 bits are the sender's Ethereum address. `parse_amount` rejects any value exceeding `u128::MAX`: [5](#0-4) 

For any sender address with at least one non-zero byte in positions 0–19 (i.e., every real user), the parsed value is astronomically larger than `u128::MAX`, so `ERR_INVALID_AMOUNT` is returned unconditionally.

The precompile returns `ExitError`, the EVM `call` opcode returns `0`, but the Solidity assembly block assigns `res` and never checks it: [6](#0-5) 

`_burn` already executed at line 55 before the precompile call, so the tokens are gone with no NEAR-side transfer ever created. [7](#0-6) 

---

### Impact Explanation

Every call to `EvmErc20V2.withdrawToNear` on a non-`error_refund` engine results in:
- EVM-side: user's ERC-20 balance reduced to zero (burned)
- NEAR-side: no `ft_transfer` promise is ever scheduled
- Net effect: **permanent, irrecoverable destruction of user funds** — the NEP-141 tokens remain locked in the connector contract with no mechanism to release them to the user

This matches the Critical impact category: **Permanent freezing of funds**.

---

### Likelihood Explanation

The `error_refund` feature is a compile-time flag with explicit `#[cfg(not(feature = "error_refund"))]` code paths throughout the codebase, meaning the engine is explicitly designed to be deployable without it. `EvmErc20V2` is the production V2 ERC-20 mirror contract. Any deployment pairing a non-`error_refund` engine binary with `EvmErc20V2` contracts triggers this for 100% of `withdrawToNear` calls. No special privileges, no race conditions, no admin compromise required — any token holder calling the standard withdrawal function loses their funds.

---

### Recommendation

1. **Guard at the Solidity level:** `EvmErc20V2.withdrawToNear` must check the return value of the assembly `call` and revert if it is `0`, so `_burn` is rolled back on precompile failure:
   ```solidity
   assembly {
       let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
       if iszero(res) { revert(0, 0) }
   }
   ```
2. **Enforce feature consistency:** Document (or enforce via build-time assertion) that `EvmErc20V2` must only be deployed alongside an engine compiled with `error_refund`. Alternatively, add a version-negotiation byte or a separate precompile entry point for V2 so the parser can distinguish V1 and V2 input layouts regardless of feature flags.
3. **Revert-before-burn pattern:** Move `_burn` to after the precompile call succeeds, or use a check-effects-interactions pattern with a success guard.

---

### Proof of Concept

**Byte-level trace for a concrete sender:**

Suppose `sender = 0xABCDEF0123456789ABCDEF0123456789ABCDEF01`, `amount = 1000` (= `0x03E8`), `recipient = "alice.near"`.

V2 input to precompile:
```
01                                         <- flag
ABCDEF0123456789ABCDEF0123456789ABCDEF01   <- sender (20 bytes)
00000000000000000000000000000000000000000000000000000000000003E8  <- amount_b (32 bytes)
616c6963652e6e656172                       <- "alice.near"
```

Without `error_refund`, `parse_input` returns `input[1..]`:
```
ABCDEF0123456789ABCDEF0123456789ABCDEF01   <- bytes 0..20
00000000000000000000000000000000000000000000000000000000000003E8  <- bytes 20..52
616c6963652e6e656172                       <- bytes 52..
```

`parse_amount(&input[..32])` reads:
```
ABCDEF0123456789ABCDEF0123456789ABCDEF01 000000000000000000000003E8
```
as a big-endian U256 ≈ `0xABCDEF...ABCDEF01_000000000000000000000003E8`

This is >> `u128::MAX` → `ERR_INVALID_AMOUNT` → `ExitError` → EVM call returns 0 → `res` ignored → `_burn` already committed → tokens permanently lost.

**Unit test sketch** (in `engine-precompiles/src/native.rs` tests, without `error_refund`):
```rust
#[cfg(not(feature = "error_refund"))]
#[test]
fn test_v2_input_parse_amount_mismatch() {
    let sender = [0xABu8; 20];
    let amount_b = [0u8; 31].iter().chain(&[0x01u8]).cloned().collect::<Vec<_>>();
    let recipient = b"alice.near";
    let mut input = vec![0x01u8];
    input.extend_from_slice(&sender);
    input.extend_from_slice(&amount_b);
    input.extend_from_slice(recipient);

    // parse_input strips only flag byte
    let remaining = &input[1..];
    // parse_amount reads sender[0..20]|amount[0..12] — must fail
    let result = parse_amount(&remaining[..32]);
    assert!(result.is_err(), "Expected ERR_INVALID_AMOUNT due to V2 layout mismatch");
}
```

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

**File:** engine-precompiles/src/native.rs (L337-345)
```rust
fn parse_amount(input: &[u8]) -> Result<U256, ExitError> {
    let amount = U256::from_big_endian(input);

    if amount > U256::from(u128::MAX) {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_AMOUNT")));
    }

    Ok(amount)
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
