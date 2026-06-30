### Title
Unchecked Exit-Precompile Return Value in `EvmErc20.sol`/`EvmErc20V2.sol` Causes Permanent Token Freeze on Failed Withdrawal — (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` burn the caller's ERC-20 tokens **before** calling the `ExitToNear` precompile, and the low-level assembly `call` return value is never inspected. If the precompile rejects the call for any reason (e.g., an invalid NEAR recipient account ID supplied by the user), the burn is already committed to EVM state, no exit promise is ever created, and the corresponding NEP-141 tokens remain permanently locked inside the Aurora contract. The user's funds are irreversibly destroyed on the EVM side with no recovery path.

---

### Finding Description

In both `EvmErc20.sol` and `EvmErc20V2.sol`, the `withdrawToNear` function follows this pattern:

```solidity
// EvmErc20.sol lines 53-63
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                        0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked
    }
}
```

The same pattern appears in `withdrawToEthereum` in both contracts.

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) validates the recipient as a NEAR `AccountId` and rejects inputs that are malformed (too long, invalid characters, non-ASCII, etc.). It also rejects calls where the ERC-20 address is not registered in the NEP-141 map, or where the amount exceeds `u128::MAX`. Any of these conditions causes the precompile to return a failure exit reason, which makes the EVM `call` opcode return `0`. Because `res` is never read, the Solidity function does not revert — it returns successfully with the tokens already burned and no promise scheduled.

The `ExitToNear` precompile's ERC-20 branch explicitly propagates errors via `?`:

```rust
// engine-precompiles/src/native.rs line 444-446
ExitToNearParams::Erc20TokenParams(ref exit_params) => {
    exit_erc20_token_to_near(context, exit_params, &self.io)?
}
```

and `exit_erc20_token_to_near` can fail on account-ID parsing or NEP-141 lookup. When it does, the precompile returns `ExitError`, the EVM `call` returns `0`, and the Solidity contract silently continues past the assembly block.

---

### Impact Explanation

**Impact: Critical — Permanent freezing of funds.**

When the precompile call fails silently:
- The user's ERC-20 mirror tokens are burned (EVM state is finalized).
- No `ft_transfer` or `ft_transfer_call` promise is ever emitted.
- The NEP-141 tokens backing those ERC-20 tokens remain locked in the Aurora engine contract with no mechanism to release them.
- There is no refund path: `refund_on_error` is only triggered by the `error_refund` feature on the NEAR callback side, which is never reached because no promise was created.

The result is a one-way destruction of user funds with no recovery.

---

### Likelihood Explanation

**Likelihood: Low.**

The most realistic trigger is a user supplying an invalid NEAR account ID as `recipient` — for example, passing a raw Ethereum address (20 bytes of arbitrary binary), a string longer than 64 characters, or a string containing characters not permitted in NEAR account IDs. The `withdrawToNear` interface accepts `bytes memory recipient` with no on-chain validation before the burn. A user unfamiliar with NEAR account ID rules can easily trigger this silently. A secondary trigger is an `amount` value exceeding `u128::MAX` (practically impossible given token supply constraints, but structurally present).

---

### Recommendation

1. **Check the precompile call return value and revert on failure:**

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                    0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

2. **Validate the recipient before burning:** Add a pre-burn check that the recipient bytes form a valid NEAR account ID (length ≤ 64, ASCII alphanumeric/`_`/`-`/`.`).

3. **Invert the operation order (burn-after-confirm):** Ideally, schedule the exit promise first and only burn on confirmed success, though this is architecturally harder given the precompile model.

---

### Proof of Concept

1. Deploy `EvmErc20.sol` (or use an existing Aurora ERC-20 mirror).
2. Mint tokens to address `A`.
3. From address `A`, call `withdrawToNear(recipient, amount)` where `recipient` is, e.g., `bytes("this-is-an-invalid-near-account-id-because-it-is-way-too-long-exceeding-64-chars")`.
4. The `_burn` executes: `A`'s ERC-20 balance drops to zero.
5. The precompile rejects the call (account ID too long) and returns failure; `res = 0`.
6. The assembly block does not revert; `withdrawToNear` returns successfully.
7. No exit promise is created. The NEP-141 tokens remain locked in the Aurora contract.
8. `A`'s tokens are permanently destroyed with no recovery. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** engine-precompiles/src/native.rs (L444-446)
```rust
                ExitToNearParams::Erc20TokenParams(ref exit_params) => {
                    exit_erc20_token_to_near(context, exit_params, &self.io)?
                }
```

**File:** engine-precompiles/src/native.rs (L558-583)
```rust
fn exit_erc20_token_to_near<I: IO>(
    context: &Context,
    exit_params: &Erc20TokenParams,
    io: &I,
) -> Result<
    (
        AccountId,
        String,
        events::ExitToNear,
        String,
        Option<TransferNearArgs>,
    ),
    ExitError,
> {
    // In case of withdrawing ERC-20 tokens, the `apparent_value` should be zero. In opposite way
    // the funds will be locked in the address of the precompile without any possibility
    // to withdraw them in the future. So, in case if the `apparent_value` is not zero, the error
    // will be returned to prevent that.
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }

    let erc20_address = context.caller; // because ERC-20 contract calls the precompile.
    let nep141_account_id = get_nep141_from_erc20(erc20_address.as_bytes(), io)?;
```
