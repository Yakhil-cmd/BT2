### Title
Unchecked Exit Precompile `call` Return Value Causes Permanent Token Burn Without Withdrawal - (`etc/eth-contracts/contracts/EvmErc20.sol` and `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20.sol` and `EvmErc20V2.sol` implement `withdrawToNear()` and `withdrawToEthereum()` by first irreversibly burning the caller's ERC-20 tokens via `_burn()`, then calling the Aurora exit precompile via inline assembly. The `res` return value of the `call` opcode is captured in a local variable but **never checked**. If the exit precompile call fails for any reason — including the precompile being paused — the function returns successfully with the tokens already destroyed and no corresponding NEP-141 release ever scheduled. This is a direct structural analog to the reported H-01 pattern: a critical sub-call return value is silently ignored, allowing a state-corrupting outcome to proceed undetected.

---

### Finding Description

In `EvmErc20.sol`, both withdrawal functions follow this pattern:

```solidity
// EvmErc20.sol – withdrawToNear (lines 53–63)
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here, irreversibly

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is NEVER checked — no `if iszero(res) { revert(...) }`
    }
}
```

`EvmErc20V2.sol` contains the identical pattern in both `withdrawToNear()` and `withdrawToEthereum()`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

The hardcoded precompile addresses are:
- `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` → `ExitToNear` precompile
- `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab` → `ExitToEthereum` precompile [5](#0-4) 

The engine's precompile dispatcher explicitly returns `PrecompileFailure::Fatal { exit_status: ExitFatal::Other("ERR_PAUSED") }` when a precompile is paused:

```rust
// engine-precompiles/src/lib.rs lines 140–143
if self.is_paused(&address) {
    return Some(Err(PrecompileFailure::Fatal {
        exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
    }));
}
``` [6](#0-5) 

A `Fatal` exit from a precompile causes the EVM `call` opcode to return `0`. Because `res` is never checked in the Solidity assembly block, the `withdrawToNear` / `withdrawToEthereum` function does not revert. The `_burn()` that already executed is not rolled back.

The pause mechanism is a first-class production feature. Authorized accounts can call `pause_precompiles` to set `PrecompileFlags::EXIT_TO_NEAR` or `PrecompileFlags::EXIT_TO_ETHEREUM`: [7](#0-6) [8](#0-7) 

The same failure mode applies to any other error path inside the precompile (e.g., `get_nep141_from_erc20` returning an error if the ERC-20 is not registered in the connector, or `ERR_ETH_ATTACHED_FOR_ERC20_EXIT` being triggered). [9](#0-8) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

When the exit precompile call returns `0` and `res` is not checked:

1. `_burn()` has already destroyed the caller's ERC-20 tokens on Aurora. This is irreversible within the transaction.
2. No NEAR promise is emitted (the precompile never ran to completion), so no NEP-141 tokens are ever released to the recipient.
3. The transaction succeeds from the EVM's perspective — no revert, no error propagated to the caller.
4. The user's bridged assets are permanently destroyed with no corresponding release on NEAR or Ethereum.

This matches the **Critical: Permanent freezing of funds** impact category.

---

### Likelihood Explanation

**Medium.** The most direct trigger is a precompile pause event, which is a documented, authorized operational action (e.g., emergency security response). During any pause window — however brief — every user who calls `withdrawToNear()` or `withdrawToEthereum()` on any `EvmErc20` or `EvmErc20V2` contract will permanently lose their tokens. Users have no on-chain signal that the precompile is paused before submitting the transaction. The pause mechanism is not a hypothetical: it is tested and exercised in the integration test suite. [10](#0-9) 

---

### Recommendation

Check `res` in every assembly block that calls an exit precompile and revert if the call failed. The fix must be applied to all four affected assembly blocks across both contracts:

```solidity
assembly {
    let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    if iszero(res) { revert(0, 0) }
}
```

Because `_burn()` is called before the precompile call, the correct ordering is either:
1. Check `res` and revert on failure (so `_burn` is rolled back by the EVM), **or**
2. Restructure to call the precompile first and only burn on success.

Option 1 is the minimal fix. Option 2 is architecturally safer.

---

### Proof of Concept

**Setup:** Deploy `EvmErc20` with a registered NEP-141 backing. Mint tokens to `alice`. Pause the `ExitToNear` precompile via `pause_precompiles(0b01)`.

**Attack sequence:**

1. `alice` holds 1000 units of an `EvmErc20` token.
2. Authorized account calls `pause_precompiles` with `EXIT_TO_NEAR` flag set.
3. `alice` calls `erc20.withdrawToNear("alice.near", 1000)`.
4. EVM executes `_burn(alice, 1000)` — alice's balance goes to 0.
5. EVM executes `call(gas(), exitToNearAddress, ...)` — precompile dispatcher returns `Fatal("ERR_PAUSED")` → `call` returns `0`.
6. `res == 0` but is never checked. No revert.
7. Transaction succeeds. Alice's 1000 ERC-20 tokens are gone. No NEP-141 tokens are released. Funds are permanently lost. [1](#0-0) [6](#0-5) [11](#0-10)

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

**File:** engine-precompiles/src/native.rs (L412-417)
```rust
        // It's not allowed to call exit precompiles in static mode
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_near::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
        }
```

**File:** engine-precompiles/src/native.rs (L817-828)
```rust
pub struct ExitToEthereum<I> {
    io: I,
}

pub mod exit_to_ethereum {
    use crate::prelude::types::{Address, make_address};

    /// Exit to Ethereum precompile address
    ///
    /// Address: `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`
    /// This address is computed as: `&keccak("exitToEthereum")[12..]`
    pub const ADDRESS: Address = make_address(0xb0bd02f6, 0xa392af548bdf1cfaee5dfa0eefcc8eab);
```

**File:** engine-precompiles/src/lib.rs (L140-144)
```rust
        if self.is_paused(&address) {
            return Some(Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
            }));
        }
```

**File:** engine/src/contract_methods/admin.rs (L225-241)
```rust
#[named]
pub fn pause_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        require_running(&state::get_state(&io)?)?;
        let authorizer: EngineAuthorizer = engine::get_authorizer(&io);

        if !authorizer.is_authorized(&env.predecessor_account_id()) {
            return Err(b"ERR_UNAUTHORIZED".into());
        }

        let args: PausePrecompilesCallArgs = io.read_input_borsh()?;
        let flags = PrecompileFlags::from_bits_truncate(args.paused_mask);
        let mut pauser = EnginePrecompilesPauser::from_io(io);
        pauser.pause_precompiles(flags);
        Ok(())
    })
}
```

**File:** engine/src/pausables.rs (L9-16)
```rust
bitflags! {
    /// Wraps unsigned integer where each bit identifies a different precompile.
    #[derive(BorshSerialize, BorshDeserialize, Default)]
    #[borsh(crate = "aurora_engine_types::borsh")]
    pub struct PrecompileFlags: u32 {
        const EXIT_TO_NEAR        = 0b01;
        const EXIT_TO_ETHEREUM    = 0b10;
    }
```

**File:** engine-tests/src/tests/pausable_precompiles.rs (L36-55)
```rust
#[test]
fn test_executing_paused_precompile_throws_error() {
    let (mut runner, mut signer, _, tester) = setup_test();

    let call_args = PausePrecompilesCallArgs {
        paused_mask: EXIT_TO_ETHEREUM_FLAG,
    };
    let input = borsh::to_vec(&call_args).unwrap();

    let _res = runner.call(PAUSE_PRECOMPILES, CALLED_ACCOUNT_ID, input);
    let is_to_near = false;
    let error = tester
        .withdraw(&mut runner, &mut signer, is_to_near)
        .unwrap_err();

    assert!(matches!(
        error.kind,
        EngineErrorKind::EvmFatal(aurora_evm::ExitFatal::Other(e)) if e == "ERR_PAUSED"
    ));
}
```
