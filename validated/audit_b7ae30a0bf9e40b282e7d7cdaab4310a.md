### Title
Unchecked `ExitToNear` Precompile Return Value in `withdrawToNear` Permanently Burns ERC-20 Mirror Tokens Without NEP-141 Transfer - (`etc/eth-contracts/contracts/EvmErc20.sol`)

---

### Summary

The `withdrawToNear` (and `withdrawToEthereum`) functions in `EvmErc20.sol` and `EvmErc20V2.sol` burn the caller's ERC-20 mirror tokens **before** calling the `ExitToNear` precompile, and never check the return value of that call. If the precompile call fails for any reason — including a user-supplied `recipient` that exceeds the precompile's hard-coded `MAX_INPUT_SIZE` of 1,024 bytes — the ERC-20 tokens are permanently destroyed while the corresponding NEP-141 tokens remain locked inside Aurora with no recovery path. This breaks the 1:1 accounting invariant between ERC-20 mirror supply and NEP-141 custody, the direct structural analog to the stock-split accounting break in the reference report.

---

### Finding Description

In `EvmErc20.sol`, `withdrawToNear` is:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);                          // (1) tokens destroyed

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                        0, add(input, 32), input_size, 0, 32)
        // (2) res is NEVER checked — no revert on failure
    }
}
```

The `ExitToNear` precompile at `engine-precompiles/src/native.rs` enforces:

```rust
const MAX_INPUT_SIZE: usize = 1_024;
// ...
fn validate_input_size(input: &[u8], min: usize, max: usize) -> Result<(), ExitError> {
    if input.len() < min || input.len() > max {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_INPUT")));
    }
    Ok(())
}
```

The precompile's `run` method calls `validate_input_size` early and returns `Err` if the input exceeds 1,024 bytes. Because `input_size = 1 + 32 + recipient.length`, any `recipient` longer than **991 bytes** causes the precompile to return an EVM-level failure (call returns `0`). Additional failure paths include an invalid NEAR account ID in `recipient` (`ERR_INVALID_RECEIVER_ACCOUNT_ID` from `parse_recipient`) and a missing `Erc20Nep141Map` entry (`ERR_TARGET_TOKEN_NOT_FOUND` from `get_nep141_from_erc20`).

In all these cases the EVM `call` opcode returns `0`, but because `res` is never inspected and no `require(res != 0)` follows, the Solidity function returns normally. The `_burn` that already executed is **not** rolled back. The ERC-20 mirror supply decreases while the NEP-141 balance held by Aurora is unchanged — the 1:1 peg is broken and the user's funds are unrecoverable.

The identical pattern exists in `EvmErc20V2.sol` `withdrawToNear` and in both contracts' `withdrawToEthereum`.

---

### Impact Explanation

**Permanent freezing of funds.** The user's ERC-20 mirror tokens are burned (gone from the EVM side). The corresponding NEP-141 tokens remain in Aurora's custody with no on-chain mechanism for the user to reclaim them. There is no refund path: the `error_refund` callback in `exit_to_near_precompile_callback` is only reachable when the precompile call *succeeds* and creates a NEAR promise that subsequently fails — it is never triggered when the precompile itself returns an EVM-level error.

---

### Likelihood Explanation

The `recipient` parameter is an unvalidated `bytes memory` value accepted directly from the caller. Any user who passes a recipient byte string longer than 991 bytes — whether by mistake, through a buggy integration contract, or through a malicious wrapper — will trigger the silent failure. The trigger requires no special privilege, no admin key, and no external oracle. It is reachable by any EVM account that holds mirror tokens.

---

### Recommendation

1. **Validate input before burning.** Check `recipient.length <= 991` (or the equivalent derived from `MAX_INPUT_SIZE`) and revert early, before `_burn` is called.
2. **Check the precompile return value.** After the `call`, add `require(res != 0, "ExitToNear failed")` inside the assembly block so that a precompile failure reverts the entire transaction, including the burn.
3. **Invert the order of operations.** Restructure so that the precompile call is attempted first (or at minimum validated) and the burn only executes once the promise is confirmed to be schedulable.

---

### Proof of Concept

1. User holds 1,000 ERC-20 mirror tokens for `usdc.near`.
2. User calls `withdrawToNear(recipient, 1000)` where `recipient` is a 1,000-byte byte string (e.g., a long NEAR account ID or garbage bytes).
3. `_burn(_msgSender(), 1000)` executes — 1,000 ERC-20 tokens are destroyed.
4. The precompile receives `input_size = 1 + 32 + 1000 = 1033 > 1024`; `validate_input_size` returns `Err("ERR_INVALID_INPUT")`; the EVM `call` returns `0`.
5. `res = 0` is never checked; `withdrawToNear` returns normally.
6. User now holds 0 ERC-20 tokens. The 1,000 NEP-141 units remain locked inside Aurora. No recovery is possible.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** engine-precompiles/src/native.rs (L37-40)
```rust
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;
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

**File:** engine-precompiles/src/native.rs (L381-420)
```rust
impl<I: IO> Precompile for ExitToNear<I> {
    fn required_gas(_input: &[u8]) -> Result<EthGas, ExitError> {
        Ok(costs::EXIT_TO_NEAR_GAS)
    }

    #[allow(clippy::too_many_lines)]
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        context: &Context,
        is_static: bool,
    ) -> EvmPrecompileResult {
        // ETH (base) transfer input format: (85 bytes)
        //  - flag (1 byte)
        //  - refund_address (20 bytes), present if the feature "error_refund" is enabled
        //  - recipient_account_id (max MAX_INPUT_SIZE - 20 - 1 bytes)
        // ERC-20 transfer input format: (124 bytes)
        //  - flag (1 byte)
        //  - refund_address (20 bytes), present if the feature "error_refund" is enabled.
        //  - amount (32 bytes)
        //  - recipient_account_id (max MAX_INPUT_SIZE - 1 - (20) - 32 bytes)
        //  - `:unwrap` suffix in a case of wNEAR (7 bytes)
        let required_gas = Self::required_gas(input)?;

        if let Some(target_gas) = target_gas
            && required_gas > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        // It's not allowed to call exit precompiles in static mode
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_near::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
        }

        let exit_to_near_params = ExitToNearParams::try_from(input)?;

```
