### Title
Unchecked Return Value of Low-Level Precompile Call After Irreversible Token Burn — (`File: etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToNear` and `withdrawToEthereum` by first burning the caller's ERC-20 tokens via `_burn()`, then invoking the Aurora exit precompile via a low-level assembly `call()`. The return value `res` of that `call()` is captured but **never checked**. If the precompile call fails for any reason, the burn is not reverted, permanently destroying the user's ERC-20 tokens while the corresponding NEP-141 tokens remain locked in Aurora's account.

### Finding Description

In `EvmErc20.sol` (lines 53–63 and 65–76) and identically in `EvmErc20V2.sol` (lines 53–64 and 66–77):

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← irreversible state change

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked — silent failure
    }
}
```

The same pattern appears in `withdrawToEthereum` (calling `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`).

The low-level `call()` invokes the `ExitToNear` / `ExitToEthereum` precompile. These precompiles can return failure (`res = 0`) in multiple reachable paths visible in `engine-precompiles/src/native.rs`:

- `get_nep141_from_erc20()` fails if the ERC-20 is not registered in the NEP-141 mapping
- `parse_amount()` or recipient parsing fails on malformed input
- `validate_input_size()` rejects out-of-range input
- `context.apparent_value != U256::zero()` guard triggers for ERC-20 exit

Because the `call()` is a low-level assembly call (not a Solidity-level call), a revert inside the precompile does **not** propagate to the outer frame. The outer function returns successfully, the `_burn()` is committed, and no promise is ever scheduled — so the `error_refund` callback mechanism is never triggered. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

**Permanent freezing of funds (Critical).**

When the precompile call silently fails:
1. The user's ERC-20 tokens are permanently burned — balance is reduced, total supply is reduced.
2. No NEAR-side `ft_transfer` promise is created, so the NEP-141 tokens remain locked in Aurora's account indefinitely.
3. There is no recovery path: the `exit_to_near_precompile_callback` refund mechanism only fires when a promise was created and then failed; here no promise is ever created.

The user suffers a total, unrecoverable loss of the withdrawn amount. [4](#0-3) [5](#0-4) 

### Likelihood Explanation

**Medium.** The failure condition is reachable by any unprivileged token holder:

- Passing a `recipient` bytes value that does not decode to a valid NEAR account ID causes `get_nep141_from_erc20` or recipient parsing inside the precompile to return an `ExitError`, making `res = 0`.
- A user who mistakenly passes a malformed recipient (e.g., an Ethereum address as raw bytes instead of a NEAR account string) will silently lose their tokens.
- No special privilege or admin access is required — `withdrawToNear` and `withdrawToEthereum` are public `external` functions callable by any token holder. [6](#0-5) [7](#0-6) 

### Recommendation

After the assembly `call()`, check `res` and revert if it is zero, so that the `_burn()` is also reverted:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

This mirrors the `safeTransfer` pattern from the original report: validate the outcome of the critical call before allowing the irreversible state change to persist. Apply the same fix to both `withdrawToNear` and `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`. [8](#0-7) [9](#0-8) 

### Proof of Concept

1. Deploy `EvmErc20` (or `EvmErc20V2`) with a registered NEP-141 mapping.
2. Mint tokens to `victim`.
3. As `victim`, call `withdrawToNear(invalidBytes, amount)` where `invalidBytes` is not a valid NEAR account ID (e.g., `0xdeadbeef`).
4. Inside the EVM: `_burn(victim, amount)` executes — victim's ERC-20 balance drops to zero.
5. The assembly `call()` to `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` fails because the precompile's `exit_erc20_token_to_near` cannot parse the recipient as a valid NEAR `AccountId` and returns `ExitError`.
6. `res = 0` — but the assembly block has no `if iszero(res) { revert(0,0) }` guard.
7. `withdrawToNear` returns successfully. No NEAR-side promise is created.
8. Victim's ERC-20 tokens are permanently gone; NEP-141 tokens remain frozen in Aurora's account. [1](#0-0) [10](#0-9) [11](#0-10)

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

**File:** engine-precompiles/src/native.rs (L419-447)
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
            };
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

**File:** engine/src/contract_methods/connector.rs (L231-239)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
```
