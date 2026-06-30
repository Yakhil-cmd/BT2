### Title
Unchecked Precompile Call Return Value After Token Burn Causes Permanent Fund Loss — (`File: etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

### Summary

Both `EvmErc20` and `EvmErc20V2` bridge token contracts burn the caller's ERC-20 tokens **before** calling the Aurora exit precompile, and then never check the return value of that low-level `call()`. If the precompile call fails for any reason reachable by a user-controlled input (e.g., an invalid NEAR recipient account ID), the tokens are permanently destroyed on the EVM side with no corresponding credit on the NEAR side.

### Finding Description

In `EvmErc20.sol` and `EvmErc20V2.sol`, both `withdrawToNear` and `withdrawToEthereum` follow the same pattern:

1. `_burn(sender, amount)` — irreversibly destroys the caller's ERC-20 tokens.
2. An inline assembly `call()` to the exit precompile (`ExitToNear` at `0xe9217bc7...` or `ExitToEthereum` at `0xb0bd02f6...`).
3. The return value `res` is assigned but **never inspected**. No `require(res != 0)` or equivalent guard exists.

```solidity
// EvmErc20.sol withdrawToNear (lines 53-63)
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // tokens destroyed here
    ...
    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, ...)
        // res is never checked
    }
}
```

The same unchecked pattern appears in:
- `EvmErc20.sol::withdrawToEthereum` (lines 65–76)
- `EvmErc20V2.sol::withdrawToNear` (lines 53–64)
- `EvmErc20V2.sol::withdrawToEthereum` (lines 66–77)

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) can return a hard `ExitError` for user-reachable conditions:

- **`ERR_TARGET_TOKEN_NOT_FOUND`** — returned by `get_nep141_from_erc20` if the ERC-20 address has no registered NEP-141 mapping. [1](#0-0) 
- **`ERR_ETH_ATTACHED_FOR_ERC20_EXIT`** — if `apparent_value != 0` during an ERC-20 exit. [2](#0-1) 
- **`ERR_PAUSED`** — if the precompile set is paused. [3](#0-2) 
- Any parse failure of the `recipient` bytes as a NEAR account ID (user-controlled input). [4](#0-3) 

When the precompile returns an `ExitError`, the EVM `call()` opcode returns `0`. Because neither `EvmErc20` nor `EvmErc20V2` checks this value, the outer transaction **succeeds** — the burn is committed, but no NEAR-side `ft_transfer` promise is ever scheduled. [5](#0-4) [6](#0-5) 

### Impact Explanation

**Critical — Permanent freezing of funds.**

A user who calls `withdrawToNear` with a recipient bytes value that the precompile rejects (e.g., a byte string that is not a valid NEAR account ID, or an account ID that is too long) will have their ERC-20 tokens burned with no corresponding NEP-141 credit on NEAR. The tokens are gone from the EVM state and never arrive on NEAR. There is no recovery path: the burn is final and no refund mechanism exists in the contract.

### Likelihood Explanation

**Medium.** Every token holder who holds an `EvmErc20`/`EvmErc20V2` bridged token and calls `withdrawToNear` is exposed. The `recipient` parameter is a raw `bytes memory` value with no on-chain validation before the burn. A user who passes an invalid NEAR account ID (e.g., an empty byte string, a string exceeding 64 characters, or one containing disallowed characters) will trigger the failure silently. This is a realistic mistake for any user interacting directly with the contract ABI rather than through a validated frontend.

### Recommendation

Check the return value of the precompile `call()` and revert if it is zero:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Apply this fix to all four affected functions in both `EvmErc20.sol` and `EvmErc20V2.sol`. Alternatively, restructure the functions to call the precompile **before** burning, and only burn if the call succeeds.

### Proof of Concept

1. Deploy `EvmErc20` on Aurora (as is done in production for any bridged NEP-141 token).
2. Mint tokens to `alice` via the admin `mint()` function.
3. `alice` calls `withdrawToNear(bytes("!!invalid!!account!!"), amount)` — the `recipient` bytes contain characters that are not valid in a NEAR account ID.
4. Inside `withdrawToNear`:
   - `_burn(alice, amount)` executes — alice's balance drops to zero. [7](#0-6) 
   - The assembly `call()` to `ExitToNear` precompile fires. The precompile attempts to parse the recipient as a NEAR `AccountId` and fails, returning `ExitError`. The EVM `call()` returns `res = 0`. [8](#0-7) 
   - `res` is never checked. [9](#0-8) 
   - The function returns without reverting.
5. Alice's ERC-20 balance is zero. No NEP-141 tokens arrive on NEAR. The tokens are permanently lost. [5](#0-4) [6](#0-5) [10](#0-9) [11](#0-10)

### Citations

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

**File:** engine-precompiles/src/native.rs (L419-446)
```rust
        let exit_to_near_params = ExitToNearParams::try_from(input)?;

        let (nep141_address, args, exit_event, method, transfer_near_args) =
            match exit_to_near_params {
                // ETH(base) token transfer
                //
                // Input slice format:
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 (base) tokens, or also can contain the `:unwrap` suffix in case of
                //  withdrawing wNEAR, or another message of JSON in case of OMNI, or address of
                //  receiver in case of transfer tokens to another engine contract.
                ExitToNearParams::BaseToken(ref exit_params) => {
                    let eth_connector_account_id = self.get_eth_connector_contract_account()?;
                    exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
                }
                // ERC-20 token transfer
                //
                // This precompile branch is expected to be called from the ERC-20 burn function.
                //
                // Input slice format:
                //  amount (U256 big-endian bytes) - the amount that was burned
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 tokens, or also can contain the `:unwrap` suffix in case of withdrawing
                //  wNEAR, or another message of JSON in case of OMNI, or address of receiver in case
                //  of transfer tokens to another engine contract.
                ExitToNearParams::Erc20TokenParams(ref exit_params) => {
                    exit_erc20_token_to_near(context, exit_params, &self.io)?
                }
```

**File:** engine-precompiles/src/native.rs (L576-580)
```rust
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }
```

**File:** engine-precompiles/src/lib.rs (L140-143)
```rust
        if self.is_paused(&address) {
            return Some(Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
            }));
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
