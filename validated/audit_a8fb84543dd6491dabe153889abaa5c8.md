Now I have all the information needed. Let me confirm the exact line numbers for the key code paths.

### Title
Unchecked Precompile Call Return Value in `withdrawToNear`/`withdrawToEthereum` Causes Permanent ERC-20 Token Freeze - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

`EvmErc20` and `EvmErc20V2` burn the caller's tokens **before** calling the exit precompile via inline assembly, and **never check the return value** of that call. When the precompile returns a non-fatal error (mapped to `PrecompileFailure::Error` by `process_precompile`), the EVM `CALL` opcode silently returns 0 to the assembly block, the outer transaction does not revert, the burn is committed, and no NEAR promise is ever scheduled. The user's ERC-20 tokens are permanently destroyed with no corresponding NEP-141 release.

---

### Finding Description

**Step 1 — Burn before call, no return-value check (`EvmErc20.sol` lines 53–63, `EvmErc20V2.sol` lines 53–64):**

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                        0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked — no `if iszero(res) { revert(0,0) }`
    }
}
```

The identical pattern appears in `withdrawToEthereum` (both contracts) calling `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`.

**Step 2 — How precompile errors propagate (`engine-precompiles/src/lib.rs` lines 164–175):**

```rust
fn process_precompile(
    p: &dyn Precompile,
    handle: &impl PrecompileHandle,
) -> Result<PrecompileOutput, PrecompileFailure> {
    p.run(input, gas_limit.map(EthGas::new), context, is_static)
        .map_err(|exit_status| PrecompileFailure::Error { exit_status })
        //                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        //  ALL ExitError variants become PrecompileFailure::Error,
        //  which causes CALL to return 0 WITHOUT reverting the outer tx.
}
```

`PrecompileFailure::Error` is the non-fatal variant. In SputnikVM (aurora-evm), it causes the `CALL` opcode to return 0 to the caller and continues outer execution. It does **not** unwind the outer transaction's state changes.

**Contrast with the paused case (`engine-precompiles/src/lib.rs` lines 140–143):**

```rust
if self.is_paused(&address) {
    return Some(Err(PrecompileFailure::Fatal {
        exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
    }));
}
```

Pausing uses `PrecompileFailure::Fatal`, which **does** revert the entire transaction. The paused path is therefore safe. Every other error path through `ExitToNear::run()` returns `ExitError`, which becomes `PrecompileFailure::Error` — the silent, non-reverting kind.

**Step 3 — Reachable `ExitError` conditions in `ExitToNear::run()` (`engine-precompiles/src/native.rs`):**

| Error string | Trigger |
|---|---|
| `ERR_INVALID_RECEIVER_ACCOUNT_ID` | Recipient bytes are not valid UTF-8 or not a valid NEAR account ID |
| `ERR_TARGET_TOKEN_NOT_FOUND` | ERC-20 address not present in the NEP-141 mapping |
| `ERR_INVALID_FLAG` | First byte of input is not `0x00` or `0x01` |
| `ERR_MISSING_FLAG` | Empty input |
| `ERR_INVALID_IN_STATIC` | Called in a static context |
| `ERR_INVALID_IN_DELEGATE` | Called via `DELEGATECALL` |
| `ERR_ETH_ATTACHED_FOR_ERC20_EXIT` | Non-zero `apparent_value` on ERC-20 exit |

All of these return `ExitError`, not `ExitFatal`. All of them therefore produce `PrecompileFailure::Error`, causing the `CALL` to return 0 silently.

---

### Impact Explanation

**Impact: Permanent freezing of funds.**

When any of the above errors occurs:

1. `_burn` has already executed and committed — the user's ERC-20 balance is reduced to zero for the withdrawn amount.
2. The precompile `CALL` returns 0.
3. The assembly block does not check `res` and does not `revert`.
4. The outer EVM transaction succeeds.
5. No NEAR cross-contract promise is ever scheduled.
6. The corresponding NEP-141 tokens remain locked inside the Aurora contract (`aurora` account) on NEAR indefinitely.
7. There is no recovery path: the ERC-20 tokens are gone and the NEP-141 tokens are unreachable.

The locked NEP-141 tokens are real user funds bridged from NEAR. Their permanent inaccessibility constitutes a permanent fund freeze.

---

### Likelihood Explanation

**Likelihood: Medium.**

The most realistic trigger is `ERR_INVALID_RECEIVER_ACCOUNT_ID`. NEAR account IDs have strict validation rules (lowercase alphanumeric, dots, dashes, underscores; max 64 characters; specific sub-account rules). A user who:

- Makes a typo in the recipient account ID,
- Uses a frontend that encodes the recipient incorrectly,
- Passes an Ethereum-style hex address as the recipient without proper encoding,

will silently lose their tokens. This is not a contrived scenario — it is a natural user-error path that the contract provides no protection against. The `withdrawToNear` function accepts arbitrary `bytes memory recipient` with no on-chain validation before burning.

The `ERR_TARGET_TOKEN_NOT_FOUND` path is lower likelihood but possible if the NEP-141 ↔ ERC-20 mapping is ever in an inconsistent state.

---

### Recommendation

1. **Check the return value** of every precompile `call` in assembly and revert on failure:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f,
                    0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

2. **Reorder operations**: validate the recipient and confirm the precompile will accept the call *before* burning tokens. Because the precompile is a NEAR-side operation, full pre-validation is not always possible in the EVM, making the return-value check the essential safety net.

3. **Apply the fix to all four call sites**: `withdrawToNear` and `withdrawToEthereum` in both `EvmErc20.sol` and `EvmErc20V2.sol`.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. User holds 1000 `EvmErc20` tokens (bridged from NEP-141 `token.near`).
2. User calls `withdrawToNear(bytes("INVALID ACCOUNT!!"), 1000)` — the recipient contains spaces and uppercase letters, which are invalid in NEAR account IDs.
3. Inside `withdrawToNear`:
   - `_burn(user, 1000)` executes — user's ERC-20 balance drops to 0.
   - Assembly `call` to `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` is made.
4. Inside `ExitToNear::run()` (`engine-precompiles/src/native.rs`):
   - `parse_recipient(b"INVALID ACCOUNT!!")` fails → returns `ExitError::Other("ERR_INVALID_RECEIVER_ACCOUNT_ID")`.
5. `process_precompile` maps this to `PrecompileFailure::Error { exit_status: ExitError::Other(...) }`.
6. The EVM `CALL` opcode returns 0 to the assembly block.
7. `res` is never checked — no `revert`.
8. The EVM transaction succeeds. The burn is final.
9. No NEAR promise is created. `token.near` NEP-141 balance of `aurora` is unchanged.
10. The user has lost 1000 tokens permanently: ERC-20 burned, NEP-141 locked.

**Relevant code locations:**

- Burn-before-call with unchecked return: [1](#0-0) 
- Same pattern in V2: [2](#0-1) 
- `ExitError` silently mapped to non-reverting `PrecompileFailure::Error`: [3](#0-2) 
- Paused path correctly uses `Fatal` (safe, contrast): [4](#0-3) 
- `ERR_INVALID_RECEIVER_ACCOUNT_ID` returned as `ExitError`: [5](#0-4) 
- `ERR_TARGET_TOKEN_NOT_FOUND` returned as `ExitError`: [5](#0-4)

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

**File:** engine-precompiles/src/lib.rs (L140-144)
```rust
        if self.is_paused(&address) {
            return Some(Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
            }));
        }
```

**File:** engine-precompiles/src/lib.rs (L173-175)
```rust
    p.run(input, gas_limit.map(EthGas::new), context, is_static)
        .map_err(|exit_status| PrecompileFailure::Error { exit_status })
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
