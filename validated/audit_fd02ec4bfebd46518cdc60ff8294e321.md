### Title
Immediate `pause_contract` by Owner Permanently Blocks Users from Withdrawing Bridged ETH - (`engine/src/contract_methods/admin.rs`, `engine/src/contract_methods/connector.rs`)

---

### Summary

The Aurora Engine owner can call `pause_contract` at any time, which takes effect immediately by setting `state.is_paused = true`. The `withdraw` function in the ETH connector — the only path for users to bridge their ETH back from NEAR to Ethereum — unconditionally calls `require_running`, which reverts with `ERR_PAUSED` when the contract is paused. Users who have deposited ETH into Aurora have no alternative withdrawal path and cannot recover their funds for the duration of the pause.

---

### Finding Description

`pause_contract` in `engine/src/contract_methods/admin.rs` is callable exclusively by the owner and takes effect in the same transaction with no timelock or delay:

```rust
pub fn pause_contract<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        require_running(&state)?;
        state.is_paused = true;          // ← immediate effect
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
``` [1](#0-0) 

`require_running` is the gate that enforces the paused state:

```rust
pub fn require_running(state: &state::EngineState) -> Result<(), ContractError> {
    if state.is_paused {
        return Err(errors::ERR_PAUSED.into());
    }
    Ok(())
}
``` [2](#0-1) 

The `withdraw` function — the user-facing entrypoint to bridge ETH from NEAR back to Ethereum — calls `require_running` as its very first check before any state mutation:

```rust
pub fn withdraw<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;   // ← reverts if paused
    env.assert_one_yocto()?;
    ...
    return_promise(io, env, "engine_withdraw", args, ONE_YOCTO)
}
``` [3](#0-2) 

There is no alternative withdrawal path for users. `ft_transfer` and `ft_transfer_call` are equally gated by `require_running`: [4](#0-3) 

---

### Impact Explanation

Users who have bridged ETH from Ethereum into Aurora hold balances inside the Aurora Engine contract. The `withdraw` function is the sole mechanism to move those funds back to Ethereum. When the owner calls `pause_contract`, this function immediately begins reverting for all callers. The funds remain locked inside the Aurora contract for the entire duration of the pause. If the owner never calls `resume_contract`, the freeze is permanent. This constitutes **temporary freezing of funds** (High) with a realistic path to **permanent freezing of funds** (Critical). [5](#0-4) 

---

### Likelihood Explanation

The owner is a single account with no on-chain timelock enforced at the contract level. A legitimate emergency pause (e.g., a discovered exploit in the bridge) would immediately and silently block all user withdrawals. Users have no advance warning and no grace period to exit. The scenario requires only the owner to act within their normal administrative role — no key compromise or malicious intent is necessary to trigger the impact. [1](#0-0) 

---

### Recommendation

Introduce a time-delayed pause mechanism. The owner should be required to first announce a pending pause (stored on-chain with a block-height deadline), and `pause_contract` should only finalize after the delay has elapsed. Alternatively, route `pause_contract` through a timelock governance contract so that users have a window to call `withdraw` before the pause takes effect. The `resume_contract` path can remain immediate since it only benefits users. [6](#0-5) 

---

### Proof of Concept

1. User bridges ETH from Ethereum to Aurora via the connector; their balance is recorded inside the Aurora Engine contract.
2. Owner calls `pause_contract` (e.g., in response to a reported vulnerability). The call succeeds immediately and sets `state.is_paused = true`.
3. User calls `withdraw` (via the `withdraw` NEAR entrypoint in `engine/src/lib.rs`) to recover their ETH.
4. `withdraw` calls `require_running(&state::get_state(&io)?)` which returns `Err(ERR_PAUSED)`.
5. The NEAR transaction panics; the user's ETH remains locked in the Aurora contract.
6. The existing test `test_withdraw_from_near_pausability` in `engine-tests-connector/src/connector.rs` already demonstrates that pausing `engine_withdraw` on the connector side blocks the `withdraw` call — the same effect is achieved at the engine level via `pause_contract`. [7](#0-6) [3](#0-2)

### Citations

**File:** engine/src/contract_methods/admin.rs (L250-272)
```rust
#[named]
pub fn pause_contract<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        require_running(&state)?;
        state.is_paused = true;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}

#[named]
pub fn resume_contract<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        require_paused(&state)?;
        state.is_paused = false;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
}
```

**File:** engine/src/contract_methods/mod.rs (L65-70)
```rust
pub fn require_running(state: &state::EngineState) -> Result<(), ContractError> {
    if state.is_paused {
        return Err(errors::ERR_PAUSED.into());
    }
    Ok(())
}
```

**File:** engine/src/contract_methods/connector.rs (L43-59)
```rust
pub fn withdraw<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    env.assert_one_yocto()?;

    let args: WithdrawCallArgs = io.read_input_borsh()?;
    let args = borsh::to_vec(&EngineWithdrawCallArgs {
        sender_id: env.predecessor_account_id(),
        recipient_address: args.recipient_address,
        amount: args.amount,
    })
    .unwrap();

    return_promise(io, env, "engine_withdraw", args, ONE_YOCTO)
}
```

**File:** engine/src/contract_methods/connector.rs (L248-285)
```rust
pub fn ft_transfer<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    env.assert_one_yocto()?;
    let args = read_json_args(&io).and_then(|args: FtTransferArgs| {
        serde_json::to_vec(&(
            env.predecessor_account_id(),
            args.receiver_id,
            args.amount,
            args.memo,
        ))
        .map_err(Into::<ParseArgsError>::into)
    })?;

    return_promise(io, env, "engine_ft_transfer", args, ONE_YOCTO)
}

pub fn ft_transfer_call<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    // Check is payable
    env.assert_one_yocto()?;
    let args = read_json_args(&io).and_then(|args: FtTransferCallArgs| {
        serde_json::to_vec(&(
            env.predecessor_account_id(),
            args.receiver_id,
            args.amount,
            args.memo,
            args.msg,
        ))
        .map_err(Into::<ParseArgsError>::into)
    })?;

    return_promise(io, env, "engine_ft_transfer_call", args, ONE_YOCTO)
```

**File:** engine/src/lib.rs (L228-236)
```rust
    /// Sets the flag to pause the contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn pause_contract() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::pause_contract(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```
