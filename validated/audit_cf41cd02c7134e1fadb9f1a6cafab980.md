### Title
Unchecked Exit-Precompile Return Value in `withdrawToNear` / `withdrawToEthereum` Causes Permanent Token Burn Without Transfer — (`etc/eth-contracts/contracts/EvmErc20.sol`)

---

### Summary

`EvmErc20.sol` burns ERC-20 tokens **before** calling the Aurora exit precompile and never checks whether that call succeeded. If the precompile reverts for any reason, the burn is not rolled back, and the user's tokens are permanently destroyed with no corresponding transfer to NEAR or Ethereum.

---

### Finding Description

Both `withdrawToNear` (lines 53–63) and `withdrawToEthereum` (lines 65–76) follow the same unsafe pattern:

```solidity
// Step 1 – irreversible state change in the outer call frame
_burn(_msgSender(), amount);

// Step 2 – sub-call to the exit precompile
assembly {
    let res := call(gas(), 0xe9217bc7…, 0, add(input, 32), input_size, 0, 32)
    // res is NEVER checked; no revert on failure
}
``` [1](#0-0) [2](#0-1) 

In the EVM execution model, `_burn` executes in the **outer call frame**. The subsequent `call` to the precompile executes in a **child frame**. If the child frame fails (returns 0), only the child frame's state changes are reverted; the `_burn` in the outer frame is **not** reverted. Because `res` is never inspected and no `revert` is issued, the outer transaction completes successfully with the tokens gone and no promise created.

The `ExitToNear` precompile (`0xe9217bc7…`) returns an `ExitError` — causing the child `call` to return 0 — in several attacker-reachable situations:

| Failure path | Trigger |
|---|---|
| `ERR_TARGET_TOKEN_NOT_FOUND` | ERC-20 not registered in the NEP-141 map (e.g. custom deployment) |
| `ERR_INVALID_RECEIVER_ACCOUNT_ID` | `recipient` bytes are not a valid NEAR account ID |
| `ERR_INVALID_AMOUNT` | `amount > u128::MAX` | [3](#0-2) [4](#0-3) 

The `ExitToEthereum` precompile (`0xb0bd02f6…`) has the same failure modes via `get_nep141_from_erc20` and `get_eth_connector_contract_account`. [5](#0-4) 

---

### Impact Explanation

**Permanent freezing (destruction) of funds.** The tokens are removed from the user's EVM balance via `_burn` and are never minted on NEAR or unlocked on Ethereum. There is no recovery path: the NEP-141 supply is unaffected (no tokens were transferred), and the ERC-20 supply is reduced, creating a permanent accounting discrepancy. This matches the **Critical – Permanent freezing of funds** impact class.

---

### Likelihood Explanation

The trigger is **user-controlled**:

- `withdrawToNear` accepts `bytes memory recipient` with no on-chain validation. Any caller can pass bytes that fail NEAR account-ID parsing (empty string, characters outside `[a-z0-9_\-.]`, length > 64, etc.). The precompile's `parse_recipient` will return `ERR_INVALID_RECEIVER_ACCOUNT_ID`, the child call returns 0, and the burn is final.
- Any ERC-20 contract that inherits `EvmErc20` but is deployed outside the engine's `deploy_erc20_token` flow (and therefore not registered in the NEP-141 map) will permanently burn every withdrawal attempt.

No special privilege is required; any token holder can trigger the loss on their own funds, and a malicious or buggy integration can trigger it on behalf of unsuspecting users.

---

### Recommendation

Check the precompile return value and revert on failure in both functions:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                    0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Alternatively, validate `recipient` as a well-formed NEAR account ID **before** calling `_burn`, so the transaction reverts early without destroying tokens.

---

### Proof of Concept

**Scenario A – invalid recipient (no special setup needed):**

1. Alice holds 100 units of a registered `EvmErc20` token on Aurora.
2. Alice calls `withdrawToNear(bytes("invalid account!"), 100)`.
3. `_burn(Alice, 100)` executes; Alice's balance drops to 0.
4. The precompile is called with `recipient = "invalid account!"`.
5. `parse_recipient` fails → `ExitError::Other("ERR_INVALID_RECEIVER_ACCOUNT_ID")` → child `call` returns 0.
6. `res` is never checked; the outer function returns normally.
7. Alice's 100 tokens are gone. No NEAR transfer promise was created. Funds are permanently lost.

**Scenario B – unregistered ERC-20:**

1. A contract inheriting `EvmErc20` is deployed directly (not via `deploy_erc20_token`).
2. Any user calls `withdrawToNear` or `withdrawToEthereum`.
3. `get_nep141_from_erc20` returns `ERR_TARGET_TOKEN_NOT_FOUND` → child `call` returns 0.
4. Tokens are burned; no transfer occurs; funds are permanently lost. [1](#0-0) [6](#0-5)

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

**File:** engine-precompiles/src/native.rs (L359-379)
```rust
fn parse_recipient(recipient: &[u8]) -> Result<Recipient<'_>, ExitError> {
    let recipient = str::from_utf8(recipient)
        .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?;
    let (receiver_account_id, message) = recipient.split_once(':').map_or_else(
        || (recipient, None),
        |(recipient, msg)| {
            if msg == UNWRAP_WNEAR_MSG {
                (recipient, Some(Message::UnwrapWnear))
            } else {
                (recipient, Some(Message::Omni(msg)))
            }
        },
    );

    Ok(Recipient {
        receiver_account_id: receiver_account_id
            .parse()
            .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?,
        message,
    })
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

**File:** engine-precompiles/src/native.rs (L930-935)
```rust
                }

                let erc20_address = context.caller;
                let nep141_address = get_nep141_from_erc20(erc20_address.as_bytes(), &self.io)?;
                let amount = parse_amount(&input[..32])?;

```
