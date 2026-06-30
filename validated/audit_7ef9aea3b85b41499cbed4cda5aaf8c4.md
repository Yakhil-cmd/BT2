### Title
Missing Zero Address Check in `ExitToEthereum` Precompile Allows Permanent Loss of Bridged Funds - (File: `engine-precompiles/src/native.rs`)

### Summary
The `ExitToEthereum` precompile in Aurora Engine accepts a user-supplied Ethereum recipient address without validating it against the zero address. Any EVM user who calls the precompile (directly or via `EvmErc20.withdrawToEthereum`) with `address(0)` as the recipient will have their tokens permanently burned on Aurora while the corresponding withdrawal is dispatched to `address(0)` on Ethereum, resulting in permanent, irrecoverable loss of funds.

### Finding Description
In `engine-precompiles/src/native.rs`, the `ExitToEthereum::run` function handles two exit paths. In both paths the Ethereum recipient address is parsed from raw user-controlled calldata with no subsequent zero-address guard.

**ETH base-token path (flag `0x0`):** [1](#0-0) 

```rust
let recipient_address: Address = input
    .try_into()
    .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS")))?;
```

**ERC-20 path (flag `0x1`):** [2](#0-1) 

```rust
let recipient_address = Address::try_from_slice(input)
    .map_err(|_| ExitError::Other(Cow::from("ERR_WRONG_ADDRESS")))?;
```

In both cases the parsed `recipient_address` is used directly to build the withdrawal promise that is dispatched to the ETH connector: [3](#0-2) 

```rust
let withdraw_promise = PromiseCreateArgs {
    target_account_id: nep141_address,
    method: "withdraw".to_string(),
    args: serialized_args,
    attached_balance: Yocto::new(1),
    attached_gas: costs::WITHDRAWAL_GAS,
};
```

The `EvmErc20` and `EvmErc20V2` Solidity contracts expose `withdrawToEthereum(address recipient, uint256 amount)` as a public entry point that feeds directly into this precompile: [4](#0-3) 

```solidity
function withdrawToEthereum(address recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);
    ...
    assembly {
        let res := call(gas(), 0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab, ...)
    }
}
```

The burn on Aurora is executed **before** the precompile call, so by the time the zero-address withdrawal is dispatched the user's tokens are already destroyed on the Aurora side.

### Impact Explanation
When `recipient = address(0)` is supplied:

1. The user's ERC-20 tokens (or ETH) are burned on Aurora — this is irreversible.
2. A `withdraw` call is dispatched to the ETH connector targeting `address(0)` on Ethereum.
3. Tokens sent to `address(0)` on Ethereum are permanently inaccessible.

The result is **permanent, total loss of the bridged funds**. There is no recovery path: the Aurora-side burn cannot be undone, and the Ethereum-side destination is the uncontrolled zero address. This satisfies the **Critical — Permanent freezing of funds** impact category.

### Likelihood Explanation
The entry point is the public `withdrawToEthereum` function on every `EvmErc20` / `EvmErc20V2` token deployed by the Aurora bridge, callable by any EVM account with a token balance. Passing `address(0)` as a recipient is a well-known user mistake (copy-paste error, uninitialized variable in a calling contract, etc.). No special privilege or prior compromise is required. Likelihood is **Medium**.

### Recommendation
Add an explicit zero-address guard in `ExitToEthereum::run` immediately after parsing the recipient address in both the ETH and ERC-20 branches:

```rust
if recipient_address == Address::zero() {
    return Err(ExitError::Other(Cow::from("ERR_ZERO_RECIPIENT_ADDRESS")));
}
```

This check should be placed before any state-mutating action (i.e., before the burn in the ERC-20 path and before the withdrawal promise is constructed in the ETH path). Analogously, `EvmErc20.withdrawToEthereum` and `EvmErc20V2.withdrawToEthereum` should add a Solidity-level guard:

```solidity
require(recipient != address(0), "ERR_ZERO_RECIPIENT");
```

### Proof of Concept
1. User holds 1000 `EvmErc20` tokens on Aurora.
2. User calls `token.withdrawToEthereum(address(0), 1000)`.
3. `_burn(msg.sender, 1000)` executes — tokens are destroyed on Aurora.
4. The inline assembly calls the `ExitToEthereum` precompile at `0xb0bd02f6...` with flag `0x01`, amount `1000`, and recipient `0x0000...0000`.
5. `ExitToEthereum::run` parses `recipient_address = Address::zero()` with no rejection.
6. A `withdraw` NEAR promise is created targeting the ETH connector with `recipient = 0x0000...0000`.
7. The ETH connector processes the withdrawal and sends tokens to `address(0)` on Ethereum.
8. Funds are permanently lost on both sides. [5](#0-4) [4](#0-3) [6](#0-5)

### Citations

**File:** engine-precompiles/src/native.rs (L844-864)
```rust
impl<I: IO> Precompile for ExitToEthereum<I> {
    fn required_gas(_input: &[u8]) -> Result<EthGas, ExitError> {
        Ok(costs::EXIT_TO_ETHEREUM_GAS)
    }

    #[allow(clippy::too_many_lines)]
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        context: &Context,
        is_static: bool,
    ) -> EvmPrecompileResult {
        // ETH (Base token) transfer input format (min size 21 bytes)
        //  - flag (1 byte)
        //  - eth_recipient (20 bytes)
        // ERC-20 transfer input format: max 53 bytes
        //  - flag (1 byte)
        //  - amount (32 bytes)
        //  - eth_recipient (20 bytes)
        validate_input_size(input, 21, 53)?;
```

**File:** engine-precompiles/src/native.rs (L893-897)
```rust
                //  eth_recipient (20 bytes) - the address of recipient which will receive ETH on Ethereum
                let recipient_address: Address = input
                    .try_into()
                    .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS")))?;
                let serialize_fn = match get_withdraw_serialize_type(&self.io)? {
```

**File:** engine-precompiles/src/native.rs (L946-947)
```rust
                    let recipient_address = Address::try_from_slice(input)
                        .map_err(|_| ExitError::Other(Cow::from("ERR_WRONG_ADDRESS")))?;
```

**File:** engine-precompiles/src/native.rs (L977-983)
```rust
        let withdraw_promise = PromiseCreateArgs {
            target_account_id: nep141_address,
            method: "withdraw".to_string(),
            args: serialized_args,
            attached_balance: Yocto::new(1),
            attached_gas: costs::WITHDRAWAL_GAS,
        };
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
