### Title
Silo Address Whitelist Removal Permanently Freezes Bridged ERC-20 Token Holders' Funds — (`engine/src/engine.rs`)

---

### Summary

In Silo mode with the `WhitelistKind::Address` whitelist enabled, if a user's EVM address is removed from the whitelist after they have received bridged ERC-20 tokens (representing locked NEP-141 assets), they can no longer submit any EVM transaction — including `withdrawToNear()` and `withdrawToEthereum()` on `EvmErc20`/`EvmErc20V2`. This results in a permanent freeze of their bridged funds with no recovery path.

---

### Finding Description

Aurora Engine's Silo mode enforces a four-tier whitelist. The `WhitelistKind::Address` list gates all EVM transaction submission. The enforcement point is `assert_access` in `engine/src/engine.rs`:

```rust
fn assert_access<I: IO + Copy, E: Env>(
    io: &I,
    env: &E,
    transaction: &NormalizedEthTransaction,
) -> Result<(), EngineError> {
    let allowed = if transaction.to.is_some() {
        silo::is_allow_submit(io, &env.predecessor_account_id(), &transaction.address)
    } else {
        silo::is_allow_deploy(io, &env.predecessor_account_id(), &transaction.address)
    };

    if !allowed {
        return Err(EngineError {
            kind: EngineErrorKind::NotAllowed,
            gas_used: 0,
        });
    }
    Ok(())
}
``` [1](#0-0) 

This is called unconditionally inside `submit_with_alt_modexp` before any EVM execution: [2](#0-1) 

`is_allow_submit` checks both the NEAR `Account` whitelist and the EVM `Address` whitelist: [3](#0-2) 

`is_address_allowed` returns `false` for any address not present in the enabled `WhitelistKind::Address` list: [4](#0-3) 

The only way for a user to exit bridged ERC-20 tokens back to NEAR is to call `withdrawToNear()` (or `withdrawToEthereum()`) on the `EvmErc20`/`EvmErc20V2` contract. Both functions are EVM transactions that must pass through `submit()`:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);
    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;
    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    }
}
``` [5](#0-4) [6](#0-5) 

There is no exception in `assert_access` for exit/withdrawal destinations (the `ExitToNear` precompile at `0xe9217bc7...` or `ExitToEthereum` at `0xb0bd02f6...`). Any address removed from the `Address` whitelist is completely blocked from submitting any EVM transaction, including the only available exit path.

The incoming token minting path (`receive_erc20_tokens`) has a fallback mechanism that redirects tokens to a configured fallback address when the recipient is not whitelisted: [7](#0-6) 

However, this fallback only applies to **incoming** minting. There is no symmetric protection for **outgoing** exits. A user who received tokens while whitelisted (or before the whitelist was enabled, or when no fallback was configured) and is later removed from the whitelist has no exit path.

---

### Impact Explanation

**Permanent freezing of funds.** The user's ERC-20 tokens represent real NEP-141 tokens locked in the bridge on the NEAR side. Once the user's EVM address is removed from the `Address` whitelist, they cannot call `withdrawToNear()` or `withdrawToEthereum()` — the only mechanisms to recover those underlying assets. The tokens are irrecoverably frozen unless the operator re-adds the address to the whitelist.

---

### Likelihood Explanation

Silo mode with the `Address` whitelist is an explicitly supported and documented production configuration. The `remove_entry_from_whitelist` entrypoint is a standard operator action: [8](#0-7) 

Realistic triggers include compliance-driven removal, user banning, or routine whitelist rotation. The existing test `test_submit_with_removing_entries` confirms that removal immediately blocks all subsequent transactions from that address: [9](#0-8) 

Any Silo deployment that (a) enables the `Address` whitelist, (b) mints ERC-20 tokens to users, and (c) later removes users from the whitelist triggers this freeze. This is a realistic operational sequence.

---

### Recommendation

In `assert_access` (`engine/src/engine.rs`), add an exception that allows non-whitelisted addresses to submit transactions **to** the `ExitToNear` precompile address (`0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`) and the `ExitToEthereum` precompile address (`0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`). This mirrors the original report's recommendation to exclude `address(this)` from the `from`-side whitelist check — here, the analogous fix is to exclude the exit precompile addresses from the `to`-side whitelist check.

Alternatively, introduce a dedicated `is_allow_exit` check that bypasses the `Address` whitelist when the transaction destination is a known exit precompile, ensuring token holders always retain the ability to exit their funds regardless of whitelist status.

---

### Proof of Concept

1. Deploy Aurora Engine in Silo mode; enable the `WhitelistKind::Address` whitelist via `set_whitelist_status`.
2. Add user's EVM address `U` to the `Address` whitelist via `add_entry_to_whitelist`.
3. User bridges NEP-141 tokens to Aurora via `ft_transfer_call` → `ft_on_transfer` → `receive_erc20_tokens`. Since `U` is whitelisted, tokens are minted to `U`'s ERC-20 balance.
4. Operator calls `remove_entry_from_whitelist` for address `U`.
5. User submits an EVM transaction calling `withdrawToNear(recipient, amount)` on the `EvmErc20` contract.
6. `submit()` → `submit_with_alt_modexp()` → `assert_access()` evaluates `silo::is_allow_submit(io, predecessor, &U)` → `is_address_allowed` returns `false` (whitelist enabled, `U` not present) → returns `EngineErrorKind::NotAllowed`.
7. The transaction is rejected. The user's ERC-20 tokens remain frozen with no recovery path. [10](#0-9) [11](#0-10) [1](#0-0)

### Citations

**File:** engine/src/engine.rs (L818-822)
```rust
        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }
```

**File:** engine/src/engine.rs (L1049-1052)
```rust
    let fixed_gas = silo::get_fixed_gas(&io);

    // Check if the sender has rights to submit transactions or deploy code.
    assert_access(&io, env, &transaction)?;
```

**File:** engine/src/engine.rs (L1756-1775)
```rust
fn assert_access<I: IO + Copy, E: Env>(
    io: &I,
    env: &E,
    transaction: &NormalizedEthTransaction,
) -> Result<(), EngineError> {
    let allowed = if transaction.to.is_some() {
        silo::is_allow_submit(io, &env.predecessor_account_id(), &transaction.address)
    } else {
        silo::is_allow_deploy(io, &env.predecessor_account_id(), &transaction.address)
    };

    if !allowed {
        return Err(EngineError {
            kind: EngineErrorKind::NotAllowed,
            gas_used: 0,
        });
    }

    Ok(())
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L91-95)
```rust
/// Remove an entry from a whitelist depending on a kind of list types in provided arguments.
pub fn remove_entry_from_whitelist<I: IO + Copy>(io: &I, args: &WhitelistArgs) {
    let (kind, entry) = get_kind_and_entry(args);
    Whitelist::init(io, kind).remove(entry);
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L135-143)
```rust
/// Check if a user has the right to submit transactions.
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}

/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L155-158)
```rust
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
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

**File:** engine-tests/src/tests/silo.rs (L642-703)
```rust
#[test]
fn test_submit_with_removing_entries() {
    let (mut runner, signer, receiver) = initialize_transfer();
    let sender = utils::address_from_secret_key(&signer.secret_key);
    let caller: AccountId = CALLER_ACCOUNT_ID.parse().unwrap();
    let transaction = utils::transfer_with_price(
        receiver,
        TRANSFER_AMOUNT,
        INITIAL_NONCE.into(),
        ONE_GAS_PRICE.raw(),
    );

    set_silo_params(&mut runner, Some(SILO_PARAMS_ARGS));
    enable_all_whitelists(&mut runner);

    // Allow submitting transactions.
    add_account_to_whitelist(&mut runner, caller.clone());
    add_address_to_whitelist(&mut runner, sender);

    validate_address_balance_and_nonce(&runner, sender, INITIAL_BALANCE, INITIAL_NONCE.into())
        .unwrap();
    validate_address_balance_and_nonce(&runner, receiver, ZERO_BALANCE, INITIAL_NONCE.into())
        .unwrap();

    // perform transfer
    let result = runner
        .submit_transaction(&signer.secret_key, transaction.clone())
        .unwrap();
    assert!(matches!(result.status, TransactionStatus::Succeed(_)));

    // validate post-state
    validate_address_balance_and_nonce(
        &runner,
        sender,
        INITIAL_BALANCE - TRANSFER_AMOUNT - FIXED_GAS * ONE_GAS_PRICE,
        (INITIAL_NONCE + 1).into(),
    )
    .unwrap();
    validate_address_balance_and_nonce(&runner, receiver, TRANSFER_AMOUNT, INITIAL_NONCE.into())
        .unwrap();

    // Remove account id and address from whitelists.
    remove_account_from_whitelist(&mut runner, caller);
    remove_address_from_whitelist(&mut runner, sender);

    // perform transfer
    let err = runner
        .submit_transaction(&signer.secret_key, transaction)
        .unwrap_err();
    assert_eq!(err.kind, EngineErrorKind::NotAllowed);

    // validate post-state
    validate_address_balance_and_nonce(
        &runner,
        sender,
        INITIAL_BALANCE - TRANSFER_AMOUNT - FIXED_GAS * ONE_GAS_PRICE,
        (INITIAL_NONCE + 1).into(),
    )
    .unwrap();
    validate_address_balance_and_nonce(&runner, receiver, TRANSFER_AMOUNT, INITIAL_NONCE.into())
        .unwrap();
}
```
