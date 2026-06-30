### Title
Silo Whitelist Bypass via `call` Entrypoint — (`engine/src/contract_methods/evm_transactions.rs`)

### Summary

In Silo mode, Aurora Engine enforces whitelist access controls on `submit` and `submit_with_args` (signed Ethereum transactions) via `assert_access`. However, the `call` and `deploy_code` entrypoints — which allow any NEAR account to execute EVM calls directly — perform no whitelist check at all. Any unprivileged NEAR account can bypass the Silo whitelist entirely by using `call` instead of `submit`.

### Finding Description

Aurora Engine's Silo mode provides a permissioned execution environment. When whitelists are enabled, only accounts/addresses in the `Account` and `Address` whitelists may submit EVM transactions, and only accounts/addresses in the `Admin` and `EvmAdmin` whitelists may deploy EVM code.

The `submit` and `submit_with_args` entrypoints enforce this via `assert_access`: [1](#0-0) 

`assert_access` checks both the NEAR predecessor account and the EVM signer address against the appropriate whitelists: [2](#0-1) 

The `is_allow_submit` and `is_allow_deploy` functions enforce the `Account`/`Address` and `Admin`/`EvmAdmin` whitelists respectively: [3](#0-2) 

However, the `call` entrypoint only checks `require_running` and never calls `assert_access`: [4](#0-3) 

Similarly, `deploy_code` only checks `require_running`: [5](#0-4) 

The NEAR-level `call` entrypoint has no access restriction either: [6](#0-5) 

### Impact Explanation

In Silo mode with whitelists enabled, the intended invariant is that only whitelisted NEAR accounts and EVM addresses may execute EVM transactions. The `call` entrypoint completely bypasses this invariant. Any NEAR account — regardless of whitelist status — can call arbitrary EVM contracts with their derived EVM address as the origin. If EVM contracts hold ETH balances or ERC-20 tokens, a non-whitelisted attacker can steal those funds. This constitutes direct theft of user funds at rest.

**Impact category**: Critical — direct theft of user funds.

### Likelihood Explanation

The `call` entrypoint is a standard public NEAR function call. Any NEAR account can invoke it with no special permissions. The attacker only needs to know the target EVM contract address and the appropriate calldata. This is trivially reachable by any unprivileged NEAR account.

### Recommendation

Apply the same `assert_access` whitelist check inside `call` and `deploy_code` that is already applied inside `submit_with_alt_modexp`. For `call`, the EVM origin address is `predecessor_address(&predecessor_account_id)`, so the check should use that address and the predecessor account ID. For `deploy_code`, the deploy whitelist (`is_allow_deploy`) should be enforced.

### Proof of Concept

1. Operator deploys Aurora Engine in Silo mode and enables all whitelists (`Account`, `Address`, `Admin`, `EvmAdmin`).
2. Operator does NOT add attacker's NEAR account or EVM address to any whitelist.
3. Attacker calls `submit` with a signed Ethereum transaction → rejected with `NotAllowed` (as confirmed by tests). [7](#0-6) 

4. Attacker instead calls `call` with `CallArgs` targeting an EVM contract holding ETH or ERC-20 tokens → **succeeds**, because `call` only checks `require_running` and never invokes `assert_access`. [4](#0-3) 

5. The EVM call executes with the attacker's derived EVM address as origin, allowing them to drain funds from any EVM contract they can interact with.

### Citations

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

**File:** engine/src/contract_methods/silo/mod.rs (L130-163)
```rust
/// Check if a user has the right to deploy EVM code.
pub fn is_allow_deploy<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_account_allowed_deploy(io, account) && is_address_allowed_deploy(io, address)
}

/// Check if a user has the right to submit transactions.
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}

/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}

fn is_account_allowed_deploy<I: IO + Copy>(io: &I, account_id: &AccountId) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Admin);
    !list.is_enabled() || list.is_exist(account_id)
}

fn is_address_allowed_deploy<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::EvmAdmin);
    !list.is_enabled() || list.is_exist(address)
}

fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}

fn is_account_allowed<I: IO + Copy>(io: &I, account: &AccountId) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Account);
    !list.is_enabled() || list.is_exist(account)
}
```

**File:** engine/src/contract_methods/evm_transactions.rs (L21-43)
```rust
pub fn deploy_code<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<SubmitResult, ContractError> {
    with_logs_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let input = io.read_input().to_vec();
        let current_account_id = env.current_account_id();
        let mut engine: Engine<_, E, AuroraModExp> = Engine::new_with_state(
            state,
            predecessor_address(&env.predecessor_account_id()),
            current_account_id,
            io,
            env,
        );
        let result = engine.deploy_code_with_input(input, None, handler)?;
        let result_bytes = borsh::to_vec(&result).map_err(|_| errors::ERR_SERIALIZE)?;
        io.return_output(&result_bytes);
        Ok(result)
    })
}
```

**File:** engine/src/contract_methods/evm_transactions.rs (L46-71)
```rust
pub fn call<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<SubmitResult, ContractError> {
    with_logs_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let bytes = io.read_input().to_vec();
        let args = CallArgs::deserialize(&bytes).ok_or(errors::ERR_BORSH_DESERIALIZE)?;
        let current_account_id = env.current_account_id();
        let predecessor_account_id = env.predecessor_account_id();

        let mut engine: Engine<_, E, AuroraModExp> = Engine::new_with_state(
            state,
            predecessor_address(&predecessor_account_id),
            current_account_id,
            io,
            env,
        );
        let result = engine.call_with_args(args, handler)?;
        let result_bytes = borsh::to_vec(&result).map_err(|_| errors::ERR_SERIALIZE)?;
        io.return_output(&result_bytes);
        Ok(result)
    })
}
```

**File:** engine/src/lib.rs (L261-270)
```rust
    /// Call method on the EVM contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn call() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::evm_transactions::call(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine-tests/src/tests/silo.rs (L462-492)
```rust
#[test]
fn test_submit_access_right() {
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

    validate_address_balance_and_nonce(&runner, sender, INITIAL_BALANCE, INITIAL_NONCE.into())
        .unwrap();
    validate_address_balance_and_nonce(&runner, receiver, ZERO_BALANCE, INITIAL_NONCE.into())
        .unwrap();

    // perform transfer
    let err = runner
        .submit_transaction(&signer.secret_key, transaction.clone())
        .unwrap_err();
    assert_eq!(err.kind, EngineErrorKind::NotAllowed);

    // validate post-state
    validate_address_balance_and_nonce(&runner, sender, INITIAL_BALANCE, INITIAL_NONCE.into())
        .unwrap();
    validate_address_balance_and_nonce(&runner, receiver, ZERO_BALANCE, INITIAL_NONCE.into())
        .unwrap();
```
