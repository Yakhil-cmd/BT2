### Title
EvmErc20 (v1) `withdrawToNear` Burns Tokens Irrecoverably When Engine Uses `error_refund` Feature — (`etc/eth-contracts/contracts/EvmErc20.sol`, `engine-precompiles/src/native.rs`)

---

### Summary

`EvmErc20` (v1) encodes its precompile input as `\x01 | amount_b(32) | recipient`. When the engine is compiled with the `error_refund` feature, `parse_input` expects `\x01 | refund_address(20) | amount(32) | recipient` and strips bytes `[1..21]` as the refund address. This shifts the remaining slice so that `parse_amount` reads a garbled 32-byte value (12 bytes of the real amount concatenated with 20 bytes of the recipient string). For any recipient ≥ 20 characters, this garbled value almost certainly exceeds `u128::MAX`, causing `parse_amount` to return `ERR_INVALID_AMOUNT`. The precompile returns an `ExitError` before scheduling any promise or refund callback. Because `EvmErc20.withdrawToNear` never checks the assembly `call` return value, the `_burn` is not reverted. Tokens are permanently destroyed with no exit and no refund.

---

### Finding Description

**Step 1 — v1 input format**

`EvmErc20.withdrawToNear` constructs:

```
input = \x01 | amount_b(32 bytes) | recipient(N bytes)
``` [1](#0-0) 

**Step 2 — `error_refund` `parse_input` misreads the layout**

With `error_refund` enabled, `MIN_INPUT_SIZE = 21` and `parse_input` reads `input[1..21]` as the `refund_address` (which is actually the first 20 bytes of `amount_b`), then returns `input[21..]` as the remaining slice. [2](#0-1) [3](#0-2) 

The remaining slice after `parse_input` is:
```
[ last 12 bytes of amount_b ] [ recipient bytes ]
```
length = `12 + N`.

**Step 3 — `parse_amount` reads a garbled 32-byte value**

For flag `0x1`, the parser does:

```rust
let amount = parse_amount(&input[..32])?;
``` [4](#0-3) 

- If `N < 20`: `&input[..32]` panics (Rust OOB on a `12 + N < 32` byte slice) → entire NEAR transaction reverts → tokens are safe.
- If `N >= 20`: the 32-byte slice is `[12 bytes of amount_b] ++ [first 20 bytes of recipient]`. The first 20 bytes of a typical ASCII NEAR account ID (e.g., `"mytoken.factory.near"`) produce a 256-bit value that overwhelmingly exceeds `u128::MAX`.

**Step 4 — `parse_amount` rejects the garbled value**

```rust
fn parse_amount(input: &[u8]) -> Result<U256, ExitError> {
    let amount = U256::from_big_endian(input);
    if amount > U256::from(u128::MAX) {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_AMOUNT")));
    }
    Ok(amount)
}
``` [5](#0-4) 

The precompile's `run` returns `Err(ExitError::Other("ERR_INVALID_AMOUNT"))`. No promise is scheduled. No refund callback is registered.

**Step 5 — The assembly `call` return value is never checked**

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
}
```

`res` is captured but never inspected. The function returns normally. The `_burn` executed at line 54 is permanent. [1](#0-0) 

**Why V2 is not affected:** `EvmErc20V2.withdrawToNear` explicitly inserts `sender` (20 bytes) between the flag and `amount_b`, matching the `error_refund` layout exactly. [6](#0-5) 

---

### Impact Explanation

Any user holding tokens in a v1 `EvmErc20` contract who calls `withdrawToNear` with a recipient NEAR account ID of 20 or more characters will have their tokens permanently burned with no corresponding NEP-141 transfer and no refund. The ERC-20 supply decreases while the NEP-141 backing supply is unchanged, creating a direct insolvency: the connector holds more NEP-141 tokens than the ERC-20 supply can account for, and the user's funds are unrecoverable.

**Impact: Critical — Insolvency / Permanent freezing of user funds.**

---

### Likelihood Explanation

- NEAR account IDs of 20+ characters are extremely common in production (e.g., `"token.v2.ref-finance.near"` = 25 chars, `"wrap.near"` = 9 chars is safe, but `"aurora-bridge.near"` = 18 chars is borderline, and many factory/bridge accounts exceed 20 chars).
- Any unprivileged EVM user can trigger this by calling `withdrawToNear` on a deployed v1 `EvmErc20` contract — no special role required.
- The only precondition is that the engine binary is compiled with `error_refund` and at least one v1 `EvmErc20` contract remains deployed.
- The attacker does not need to be malicious; ordinary users withdrawing to long account IDs will trigger this inadvertently.

---

### Recommendation

1. **Immediate:** Upgrade all deployed `EvmErc20` v1 contracts to `EvmErc20V2`, or pause v1 contracts if the engine is compiled with `error_refund`.
2. **In `EvmErc20.withdrawToNear`:** Check the assembly `call` return value and revert if it is 0:
   ```solidity
   assembly {
       let res := call(...)
       if iszero(res) { revert(0, 0) }
   }
   ```
   This ensures `_burn` is always atomically paired with a successful precompile call.
3. **In the precompile:** Add a format-version guard or detect the v1 layout (no embedded sender address) and reject it with a clear error before burning is possible — though this is secondary since the Solidity fix is the correct layer.

---

### Proof of Concept

**Setup:** Engine compiled with `error_refund`. A v1 `EvmErc20` contract is deployed. Attacker holds 1000 tokens.

**Trigger:**
```solidity
// recipient = "mytoken.factory.bridge.near" (26 chars, >= 20)
evmErc20.withdrawToNear("mytoken.factory.bridge.near", 1000);
```

**Trace:**
1. `_burn(attacker, 1000)` — balance decremented, supply reduced.
2. Input to precompile: `\x01 | [0x00..00 0x03 0xE8](32 bytes) | "mytoken.factory.bridge.near"`
3. `parse_input` (error_refund): `refund_address = input[1..21]` = first 20 bytes of amount_b = `0x0000000000000000000000000000000000000000000003E8`[0..20] = all zeros except last bytes. Remaining: `input[21..]` = last 12 bytes of amount_b + "mytoken.factory.bridge.near".
4. `parse_amount(&input[..32])`: reads 12 bytes of amount_b + "mytoken.factory.brid" (20 bytes ASCII). The resulting U256 has non-zero high bytes from ASCII values (e.g., `'m'=0x6D`), far exceeding `u128::MAX`. Returns `Err("ERR_INVALID_AMOUNT")`.
5. Precompile returns `ExitError`. Inner `call` returns 0. `res` is ignored.
6. `withdrawToNear` returns normally. `_burn` is final.
7. **1000 tokens burned. No NEP-141 transfer. No refund. Funds unrecoverable.** [1](#0-0) [7](#0-6) [4](#0-3) [5](#0-4)

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

**File:** engine-precompiles/src/native.rs (L36-40)
```rust
#[cfg(not(feature = "error_refund"))]
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;
const MAX_INPUT_SIZE: usize = 1_024;
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

**File:** engine-precompiles/src/native.rs (L739-785)
```rust
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
}

#[cfg(feature = "error_refund")]
fn parse_input(input: &[u8]) -> Result<(Address, &[u8]), ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    let mut buffer = [0; 20];
    buffer.copy_from_slice(&input[1..21]);
    let refund_address = Address::from_array(buffer);
    Ok((refund_address, &input[21..]))
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
