### Title
Missing Zero-Address Validation in `withdrawToEthereum` Causes Permanent Fund Loss - (File: `etc/eth-contracts/contracts/EvmErc20.sol`)

### Summary
Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToEthereum` with a burn-before-validate pattern and no check that the Ethereum `recipient` is non-zero. A token holder who passes `address(0)` as the recipient will have their ERC-20 tokens permanently burned on Aurora while the corresponding withdrawal is directed to the uncontrolled zero address on Ethereum, resulting in irrecoverable fund loss.

### Finding Description
The `withdrawToEthereum` function in both `EvmErc20.sol` and `EvmErc20V2.sol` follows this sequence:

1. Burns the caller's ERC-20 tokens unconditionally via `_burn(_msgSender(), amount)`.
2. Encodes the `recipient` (which may be `address(0)`) into the precompile calldata.
3. Calls the `ExitToEthereum` precompile at `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab` via inline assembly.
4. **Never checks the return value** (`res`) of the assembly `call`. [1](#0-0) 

```solidity
function withdrawToEthereum(address recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // tokens burned first, no validation

    bytes32 amount_b = bytes32(amount);
    bytes20 recipient_b = bytes20(recipient);  // address(0) accepted silently
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient_b);
    uint input_size = 1 + 32 + 20;

    assembly {
        let res := call(gas(), 0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab, 0, add(input, 32), input_size, 0, 32)
        // res is never checked
    }
}
```

The same pattern is present in `EvmErc20V2.sol`: [2](#0-1) 

On the precompile side, `ExitToEthereum::run` in `engine-precompiles/src/native.rs` parses the 20-byte recipient field for the ERC-20 case (flag `0x1`) and validates only that `input.len() == 20`. It performs **no zero-address check**: [3](#0-2) 

The precompile then constructs a `withdraw` promise to the eth-connector with the zero address as the Ethereum recipient, and the withdrawal proceeds: [4](#0-3) 

There are two compounding root causes:
- **No recipient validation**: Neither the Solidity contract nor the precompile rejects `address(0)` as the Ethereum recipient.
- **Unchecked assembly call return value**: If the precompile call fails for any reason (e.g., eth-connector account not configured), the Solidity function returns normally after burning tokens, with no withdrawal ever initiated.

### Impact Explanation
**Critical — Permanent freezing/loss of funds.**

When a user calls `withdrawToEthereum(address(0), amount)`:
- Their ERC-20 tokens are burned on Aurora (irreversible).
- The `ExitToEthereum` precompile creates a `withdraw` promise to the eth-connector targeting `address(0)` on Ethereum.
- The eth-connector processes the withdrawal to `address(0)`, an address no one controls.
- The tokens are permanently lost on both sides of the bridge.

The unchecked `call` return value compounds this: if the precompile reverts for any reason, tokens are burned with no withdrawal promise created at all, also resulting in permanent loss.

### Likelihood Explanation
**Medium.** Any ERC-20 token holder on Aurora can trigger this by calling `withdrawToEthereum` directly with `address(0)` or any other invalid/unintended Ethereum address. This can occur through:
- A user mistake (copy-paste error, uninitialized variable in a calling contract).
- A malicious contract that calls `withdrawToEthereum` on behalf of a victim after obtaining approval.

The `IExit` interface is public and the function is `external`, making it reachable by any unprivileged EVM user or contract. [5](#0-4) 

### Recommendation
1. **Add a zero-address guard** in `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`:
   ```solidity
   require(recipient != address(0), "ERR_ZERO_RECIPIENT");
   ```
2. **Check the assembly `call` return value** and revert if the precompile call fails, so tokens are never burned when the bridge operation cannot proceed:
   ```solidity
   assembly {
       let res := call(...)
       if iszero(res) { revert(0, 0) }
   }
   ```
3. Optionally, add the same zero-address guard in the `ExitToEthereum` precompile (`engine-precompiles/src/native.rs`) as a defense-in-depth measure.

### Proof of Concept
```solidity
// Any ERC-20 token holder on Aurora calls:
EvmErc20(tokenAddress).withdrawToEthereum(address(0), 1_000e18);

// Result:
// 1. 1_000e18 ERC-20 tokens burned from caller's balance (irreversible).
// 2. ExitToEthereum precompile called with recipient = 0x0000...0000.
// 3. eth-connector withdraw promise created targeting address(0) on Ethereum.
// 4. Tokens permanently lost — address(0) is uncontrolled on Ethereum.
```

### Citations

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

**File:** engine-precompiles/src/native.rs (L938-965)
```rust
                if input.len() == 20 {
                    // Parse ethereum address in hex
                    let mut buffer = [0; 40];
                    hex::encode_to_slice(input, &mut buffer).unwrap();
                    let recipient_in_hex = str::from_utf8(&buffer).map_err(|_| {
                        ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS"))
                    })?;
                    // unwrap cannot fail since we checked the length already
                    let recipient_address = Address::try_from_slice(input)
                        .map_err(|_| ExitError::Other(Cow::from("ERR_WRONG_ADDRESS")))?;

                    (
                        nep141_address,
                        // There is no way to inject json, given the encoding of both arguments
                        // as decimal and hexadecimal respectively.
                        format!(
                            r#"{{"amount": "{}", "recipient": "{}"}}"#,
                            amount.as_u128(),
                            recipient_in_hex
                        )
                        .into_bytes(),
                        events::ExitToEth {
                            sender: Address::new(erc20_address),
                            erc20_address: Address::new(erc20_address),
                            dest: recipient_address,
                            amount,
                        },
                    )
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

**File:** etc/eth-contracts/contracts/IExit.sol (L4-8)
```text
interface IExit {
    function withdrawToNear(bytes memory recipient, uint256 amount) external;

    function withdrawToEthereum(address recipient, uint256 amount) external;
}
```
