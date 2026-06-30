### Title
Missing Silo Whitelist Check in `call()` Allows Unauthorized EVM Execution — (File: engine/src/contract_methods/evm_transactions.rs)

### Summary
The `call` NEAR contract method does not enforce silo whitelist restrictions. Any NEAR account can invoke it to execute EVM calls even when silo-mode whitelists are fully enabled, bypassing the access control that `submit` and `submit_with_args` correctly enforce.

### Finding Description
Aurora Engine's silo mode uses four whitelists (`Admin`, `EvmAdmin`, `Account`, `Address`) to restrict which NEAR accounts and EVM addresses may submit transactions. The `submit` and `submit_with_args` entry points enforce this via `assert_access`: [1](#0-0) 

`assert_access` internally calls `silo::is_allow_submit`, which checks both the `Account` and `Address` whitelists: [2](#0-1) 

The `call` function, however, only checks `require_running` and proceeds directly to EVM execution with no whitelist gate: [3](#0-2) 

The EVM origin address is derived deterministically from the NEAR predecessor account ID: [4](#0-3) 

Because `call` is a public NEAR contract method with no role restriction beyond `require_running`, any NEAR account — whitelisted or not — can use it to execute arbitrary EVM calls as their implicit EVM address.

### Impact Explanation
In silo mode the operator's intent is that only whitelisted accounts may interact with the EVM. The `call` bypass lets a non-whitelisted NEAR account act as its own EVM address. If that address holds ERC-20 or ETH balances (e.g., deposited before the whitelist was activated, or received via an EVM transfer), the attacker can freely transfer or drain those balances, constituting **theft of unclaimed yield / High** and potentially **direct theft of user funds / Critical** depending on the token balances held at the implicit address.

### Likelihood Explanation
High. The `call` method is an unconditionally public NEAR contract entry point. No special key, role, or deposit is required. Any NEAR account on mainnet can call it at any time while the contract is running.

### Recommendation
Add a silo whitelist check inside `call` analogous to the `assert_access` call in `submit`. Concretely, after `require_running`, derive the caller's EVM address and verify it against `silo::is_allow_submit` (or a dedicated `is_allow_call` helper) before proceeding to `engine.call_with_args`.

### Proof of Concept
1. Deploy Aurora Engine and enable silo mode with the `Account` and `Address` whitelists active (only a single trusted NEAR account and its EVM address are whitelisted).
2. Fund the implicit EVM address of a **non-whitelisted** NEAR account `attacker.near` with ERC-20 tokens (e.g., via an EVM-level transfer from a whitelisted address).
3. From `attacker.near`, call the public NEAR method `call` with `CallArgs` targeting an ERC-20 `transfer` to an attacker-controlled address.
4. Observe that the call succeeds and the tokens are transferred — `submit` from the same account would have been rejected by `assert_access` with `ERR_NOT_ALLOWED`, but `call` has no such gate. [3](#0-2) [5](#0-4) [6](#0-5)

### Citations

**File:** engine/src/engine.rs (L1050-1055)
```rust

    // Check if the sender has rights to submit transactions or deploy code.
    assert_access(&io, env, &transaction)?;

    // Validate the chain ID, if provided inside the signature:
    if let Some(chain_id) = transaction.chain_id
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

**File:** engine/src/contract_methods/evm_transactions.rs (L45-71)
```rust
#[named]
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
