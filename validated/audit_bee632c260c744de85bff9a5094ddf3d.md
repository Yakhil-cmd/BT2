### Title
Unchecked Precompile `call()` Return Value Causes Permanent Token Loss in `withdrawToNear()` — (`File: etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToNear()` and `withdrawToEthereum()` by first burning the caller's tokens and then invoking the exit precompile via inline assembly. The return value of the assembly `call()` opcode is captured in a local variable `res` but is **never checked**. If the precompile call fails for any reason, the EVM-side burn is irreversible, the NEAR-side credit never occurs, and the user's tokens are permanently destroyed.

---

### Finding Description

In `EvmErc20.sol`, `withdrawToNear()` executes as follows:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);                          // ← tokens destroyed first

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // ❌ res is NEVER checked — silent failure allowed
    }
}
``` [1](#0-0) 

The identical pattern exists in `EvmErc20V2.sol`: [2](#0-1) 

And in `withdrawToEthereum()` in both contracts: [3](#0-2) 

The `ExitToNear` precompile enforces several hard failure conditions in Rust. Specifically, `validate_input_size` rejects any input outside `[MIN_INPUT_SIZE, MAX_INPUT_SIZE]`: [4](#0-3) 

`MAX_INPUT_SIZE` is 1,024 bytes: [5](#0-4) 

For `withdrawToNear()`, the assembled input is `1 + 32 + recipient.length` bytes. Any `recipient` longer than **991 bytes** causes the precompile to return `ExitError`, making the EVM `call()` return `0`. Because `res` is never inspected, the Solidity function returns normally — after having already burned the caller's tokens.

Additional precompile failure paths that produce the same outcome:

- `recipient` contains invalid UTF-8 → `ERR_INVALID_RECEIVER_ACCOUNT_ID`
- `recipient` encodes a syntactically invalid NEAR account ID → `ERR_INVALID_RECEIVER_ACCOUNT_ID`
- The ERC-20 address has no NEP-141 mapping registered → `ERR_TARGET_TOKEN_NOT_FOUND` [6](#0-5) 

All of these are reachable by an ordinary, unprivileged EVM user through the public `withdrawToNear()` entry point.

---

### Impact Explanation

**Critical — Permanent freezing / destruction of funds.**

The sequence is:

1. User calls `withdrawToNear(recipient, amount)`.
2. `_burn(_msgSender(), amount)` executes and is irreversible.
3. The precompile `call()` fails (returns `0`).
4. `res` is never checked; the function returns `()` with no revert.
5. No NEAR-side `ft_transfer` promise is ever created.
6. The user's EVM tokens are gone and no NEAR tokens are credited. There is no recovery path.

The same applies to `withdrawToEthereum()`, though the fixed-size input makes accidental triggering less likely there.

---

### Likelihood Explanation

**Medium.** The `recipient` parameter is a raw `bytes` value supplied by the caller. A user who passes a recipient string longer than 991 bytes, or any bytes that are not valid UTF-8 / a valid NEAR account ID, will silently lose their entire `amount`. This can occur through:

- Ordinary user error (copy-paste of a malformed address).
- A buggy front-end or integration that does not validate recipient length.
- A malicious actor tricking a user into submitting a crafted recipient.

The burn-before-call ordering means there is no safe retry; the state is already mutated before the failure is observable.

---

### Recommendation

**Option A (preferred):** Check `res` inside the assembly block and revert on failure:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

**Option B:** Validate all inputs (recipient length, UTF-8 validity, account-ID format) in Solidity before burning, so the burn only executes when the precompile call is guaranteed to succeed.

Apply the same fix to both `withdrawToNear()` and `withdrawToEthereum()` in both `EvmErc20.sol` and `EvmErc20V2.sol`.

---

### Proof of Concept

1. Deploy `EvmErc20` with a registered NEP-141 mapping.
2. Mint `10_000e18` tokens to `attacker`.
3. Call `withdrawToNear(oversized_recipient, 10_000e18)` where `oversized_recipient` is 992+ bytes.
4. Observe:
   - `balanceOf(attacker)` → `0` (tokens burned).
   - No NEAR-side `ft_transfer` promise was created (precompile returned `0`).
   - `withdrawToNear()` returned without reverting.
   - Tokens are permanently destroyed.

Expected trace:

```
[EvmErc20::withdrawToNear]
  ├─ _burn(attacker, 10_000e18)          ← succeeds, balance → 0
  ├─ call(exitToNear, oversized_input)
  │   └─ ← 0  ⚠️  PRECOMPILE REJECTED (ERR_INVALID_INPUT) — NOT DETECTED
  └─ ← [Stop]  ❌ continues despite failure

RESULT: 10,000 tokens PERMANENTLY DESTROYED
```

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

**File:** engine-precompiles/src/native.rs (L40-40)
```rust
const MAX_INPUT_SIZE: usize = 1_024;
```

**File:** engine-precompiles/src/native.rs (L295-300)
```rust
fn validate_input_size(input: &[u8], min: usize, max: usize) -> Result<(), ExitError> {
    if input.len() < min || input.len() > max {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_INPUT")));
    }
    Ok(())
}
```

**File:** engine-precompiles/src/native.rs (L302-309)
```rust
fn get_nep141_from_erc20<I: IO>(erc20_token: &[u8], io: &I) -> Result<AccountId, ExitError> {
    AccountId::try_from(
        io.read_storage(bytes_to_key(KeyPrefix::Erc20Nep141Map, erc20_token).as_slice())
            .map(|s| s.to_vec())
            .ok_or(ExitError::Other(Cow::Borrowed(ERR_TARGET_TOKEN_NOT_FOUND)))?,
    )
    .map_err(|_| ExitError::Other(Cow::Borrowed("ERR_INVALID_NEP141_ACCOUNT")))
}
```
