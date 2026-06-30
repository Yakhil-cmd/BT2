### Title
Unchecked Exit Precompile Return Value Causes Permanent Token Loss on Withdrawal Failure - (File: `etc/eth-contracts/contracts/EvmErc20.sol`)

### Summary
The `withdrawToNear` and `withdrawToEthereum` functions in `EvmErc20.sol` and `EvmErc20V2.sol` burn the caller's ERC-20 tokens **before** invoking the exit precompile via inline assembly. The return value of that `call` is captured in `res` but never checked. If the exit precompile fails for any reason, the function returns normally without reverting, leaving the user's tokens permanently burned with no corresponding NEP-141 or Ethereum-side credit.

### Finding Description

In `EvmErc20.sol`, both withdrawal functions follow this pattern:

```solidity
_burn(_msgSender(), amount);   // tokens destroyed first — irreversible
// ...
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    // res is NEVER checked
}
``` [1](#0-0) [2](#0-1) 

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) can fail for several independently reachable reasons:

1. **Precompile paused**: The engine owner can pause the `ExitToNear` precompile via `EnginePrecompilesPauser`. Any withdrawal during a pause window silently destroys tokens.
2. **Token not registered**: `get_nep141_from_erc20` returns `ERR_TARGET_TOKEN_NOT_FOUND` if the ERC-20 address is not in the NEP-141 ↔ ERC-20 bijection map — e.g., during a deployment race condition or after a deregistration.
3. **Input too large**: `validate_input_size` enforces `MAX_INPUT_SIZE = 1_024`. Since the input is `1 + 32 + recipient.length`, any `recipient` longer than 991 bytes causes the precompile to return failure.
4. **Invalid recipient encoding**: If `recipient` bytes are not valid UTF-8 or not a valid NEAR account ID, `parse_recipient` returns an error. [3](#0-2) [4](#0-3) 

In all these cases the assembly `call` returns `0`, but because `res` is never checked and there is no `require(res != 0)`, the Solidity function completes successfully. The ERC-20 tokens are irreversibly burned, but no NEP-141 transfer is scheduled on the NEAR side.

`EvmErc20V2.sol` carries the identical flaw in both its `withdrawToNear` and `withdrawToEthereum` implementations. [5](#0-4) [6](#0-5) 

The analog to the external report is direct: just as the lending protocol seizes collateral without verifying market entry (skipping oracle sanity checks), here the ERC-20 contract destroys tokens without verifying the bridge exit succeeded (skipping the precompile result check). In both cases a critical accounting validation is bypassed, leading to incorrect fund movements.

### Impact Explanation

Any user who calls `withdrawToNear` or `withdrawToEthereum` while the exit precompile is in a failure state will have their ERC-20 tokens permanently burned with no corresponding credit on NEAR or Ethereum. This is **permanent destruction/freezing of user funds** — Critical impact under the allowed scope.

### Likelihood Explanation

The precompile can legitimately be paused by the engine owner for maintenance or emergency response. During any such pause window, every withdrawal attempt silently destroys tokens. Additionally, if an ERC-20 contract is deployed before its NEP-141 mapping is written (a deployment race condition), early withdrawal calls also silently burn tokens. The entry path is fully reachable by any unprivileged token holder calling the standard `withdrawToNear` / `withdrawToEthereum` interface — no special role or privilege is required on the caller's side.

### Recommendation

Add a check on the assembly `call` return value and revert if the precompile call fails:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This ensures that if the exit precompile fails for any reason, the entire transaction reverts, the `_burn` is rolled back, and the user's tokens are preserved. Apply the same fix to `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`.

### Proof of Concept

1. Deploy `EvmErc20` for a registered NEP-141 token.
2. Engine owner pauses the `ExitToNear` precompile (a routine maintenance action).
3. User calls `withdrawToNear(recipient, 1_000e18)`.
4. `_burn(msg.sender, 1_000e18)` executes — 1 000 tokens are destroyed on-chain.
5. The assembly `call` to precompile address `0xe9217bc7...` returns `0` (precompile is paused).
6. `res` is never checked; the Solidity function returns normally with no revert.
7. The user's 1 000 tokens are permanently gone; no NEP-141 `ft_transfer` is ever scheduled on the NEAR side. [1](#0-0) [7](#0-6)

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

**File:** engine-precompiles/src/native.rs (L36-40)
```rust
#[cfg(not(feature = "error_refund"))]
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;
const MAX_INPUT_SIZE: usize = 1_024;
```

**File:** engine-precompiles/src/native.rs (L295-309)
```rust
fn validate_input_size(input: &[u8], min: usize, max: usize) -> Result<(), ExitError> {
    if input.len() < min || input.len() > max {
        return Err(ExitError::Other(Cow::from("ERR_INVALID_INPUT")));
    }
    Ok(())
}

fn get_nep141_from_erc20<I: IO>(erc20_token: &[u8], io: &I) -> Result<AccountId, ExitError> {
    AccountId::try_from(
        io.read_storage(bytes_to_key(KeyPrefix::Erc20Nep141Map, erc20_token).as_slice())
            .map(|s| s.to_vec())
            .ok_or(ExitError::Other(Cow::Borrowed(ERR_TARGET_TOKEN_NOT_FOUND)))?,
    )
    .map_err(|_| ExitError::Other(Cow::Borrowed("ERR_INVALID_NEP141_ACCOUNT")))
}
```

**File:** engine-precompiles/src/native.rs (L381-417)
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
