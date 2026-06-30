### Title
Engine Pause Blocks User Bridge Withdrawals and ERC-20 Exits Without Grace Period - (File: engine/src/contract_methods/connector.rs)

### Summary

When the Aurora Engine is paused via `pause_contract`, all user-facing bridge exit functions (`withdraw`, `ft_on_transfer`, `ft_transfer`, `ft_transfer_call`) are blocked by `require_running`. However, the `ExitToNear` and `ExitToEthereum` precompiles — the EVM-level bridge exit paths — are governed by a **separate, independent** pause mechanism (`pause_precompiles`). This means the two pause systems are not synchronized: the engine-level pause blocks NEAR-side bridge withdrawals but does not automatically pause the EVM-level exit precompiles, and vice versa. More critically, when the engine is paused, users with funds on Aurora cannot exit to NEAR or Ethereum via the NEAR-side connector methods, and there is no grace period upon `resume_contract` to allow users who were blocked during the pause to safely exit before any adverse state (e.g., a changed connector account, a changed owner, or a new contract upgrade) takes effect.

### Finding Description

The Aurora Engine has two independent pause mechanisms:

**1. Engine-level pause** (`pause_contract` / `resume_contract`):
Sets `state.is_paused = true` in `EngineState`. All mutative NEAR-callable methods check `require_running(&state)` at entry. This blocks:
- `withdraw` (ETH bridge exit to Ethereum)
- `ft_on_transfer` (NEP-141 deposit into Aurora EVM)
- `ft_transfer` / `ft_transfer_call` (NEP-141 transfers)
- `submit` / `submit_with_args` / `call` / `deploy_code` (all EVM execution)
- `exit_to_near_precompile_callback` (the NEAR-side callback for the ExitToNear precompile)

**2. Precompile-level pause** (`pause_precompiles` / `resume_precompiles`):
Independently pauses `ExitToNear` and/or `ExitToEthereum` precompiles via a bitmask stored separately in `EnginePrecompilesPauser`.

The critical issue is: **when the engine is paused, `resume_contract` immediately restores full operation with no grace period**. During the pause window, users cannot call `withdraw` to exit their ETH to Ethereum, cannot call `ft_transfer_call` to move NEP-141 tokens, and cannot use `exit_to_near_precompile_callback` (which is also gated by `require_running`). Upon `resume_contract`, the contract is immediately live again — but if the owner used the pause window to stage and deploy a contract upgrade (`stage_upgrade` requires running, but `deploy_upgrade` also checks `require_running`), or to change the eth-connector contract account (`set_eth_connector_contract_account`), users who were blocked during the pause may find themselves in an unfavorable state the moment the contract resumes, with no window to react before a new pause or upgrade cycle.

More concretely: the `exit_to_near_precompile_callback` function — the callback that completes the wNEAR unwrap flow and transfers NEAR to the user — also calls `require_running`. If the engine is paused **after** the EVM transaction that triggered `ExitToNear` was submitted but **before** the callback executes, the callback will fail. The refund path in `exit_to_near_precompile_callback` also calls `engine::refund_on_error`, which itself requires the engine to be running. This means a user's funds can be in a limbo state: the EVM-side burn has occurred, the NEAR-side transfer has not completed, and the refund path is also blocked.

### Impact Explanation

**High — Temporary freezing of funds.**

When the engine is paused:
- Users with ETH on Aurora cannot call `withdraw` to exit to Ethereum.
- Users cannot call `ft_transfer_call` to move NEP-141 tokens out.
- In-flight `ExitToNear` operations (where the EVM burn has occurred but the `exit_to_near_precompile_callback` has not yet executed) will fail their callback, and the refund path (`refund_on_error`) is also blocked by `require_running`, leaving funds in limbo until the engine resumes.

The duration of the freeze is bounded by the pause duration (owner-controlled), but there is no on-chain guarantee of a maximum pause duration or a grace period post-resume.

### Likelihood Explanation

**Medium.** The `pause_contract` function is an intentional administrative feature. The owner can pause the engine at any time for any reason (security incident, upgrade, etc.). The scenario where an in-flight `ExitToNear` callback is blocked is a realistic race condition whenever a pause occurs during active bridge usage. The lack of a grace period on `resume_contract` is a design gap that mirrors exactly the reported vulnerability class.

### Recommendation

1. Add a `min_resume_timestamp` storage variable set to `block_timestamp() + GRACE_PERIOD` when `resume_contract` is called. Gate `pause_contract` (re-pause) with a check that `block_timestamp() >= min_resume_timestamp`.
2. Exempt `exit_to_near_precompile_callback` from the `require_running` check, or at minimum exempt its refund path, so that in-flight bridge exits can complete or refund even while the engine is paused.
3. Consider synchronizing the engine-level pause with the precompile-level pause so that pausing the engine also pauses the exit precompiles (preventing new exits from being initiated while existing ones cannot complete their callbacks).

### Proof of Concept

**Step 1:** User calls `submit` with an EVM transaction that invokes the `ExitToNear` precompile to unwrap wNEAR. The EVM executes, burns the ERC-20, and schedules a NEAR promise to call `exit_to_near_precompile_callback`.

**Step 2:** Before the callback receipt executes, the owner calls `pause_contract`:

```
pause_contract → state.is_paused = true
``` [1](#0-0) 

**Step 3:** The `exit_to_near_precompile_callback` receipt executes. It calls `require_running(&state)`:

```rust
pub fn exit_to_near_precompile_callback(...) {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;   // <-- PANICS: ERR_PAUSED
``` [2](#0-1) 

The callback fails. The refund path (`refund_on_error`) is inside the same `require_running`-gated block and is also unreachable: [3](#0-2) 

**Step 4:** The user's wNEAR ERC-20 tokens have been burned on the EVM side, but the NEAR transfer has not occurred and the refund has not occurred. The user's funds are frozen until the engine is resumed.

**Step 5:** The user attempts to call `withdraw` to exit ETH to Ethereum while paused:

```rust
pub fn withdraw(...) {
    require_running(&state::get_state(&io)?)?;  // <-- ERR_PAUSED
``` [4](#0-3) 

All bridge exit paths are blocked. The `require_running` guard is the root cause: [5](#0-4) 

The engine-level pause (`is_paused` in `EngineState`) and the precompile-level pause (`EnginePrecompilesPauser`) are independent, with no synchronization or grace period on `resume_contract`: [6](#0-5) [7](#0-6)

### Citations

**File:** engine/src/contract_methods/admin.rs (L250-260)
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
```

**File:** engine/src/contract_methods/admin.rs (L262-272)
```rust
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

**File:** engine/src/contract_methods/connector.rs (L43-48)
```rust
pub fn withdraw<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    env.assert_one_yocto()?;
```

**File:** engine/src/contract_methods/connector.rs (L196-204)
```rust
pub fn exit_to_near_precompile_callback<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        env.assert_private_call()?;
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

**File:** engine/src/contract_methods/mod.rs (L65-70)
```rust
pub fn require_running(state: &state::EngineState) -> Result<(), ContractError> {
    if state.is_paused {
        return Err(errors::ERR_PAUSED.into());
    }
    Ok(())
}
```

**File:** engine/src/pausables.rs (L9-17)
```rust
bitflags! {
    /// Wraps unsigned integer where each bit identifies a different precompile.
    #[derive(BorshSerialize, BorshDeserialize, Default)]
    #[borsh(crate = "aurora_engine_types::borsh")]
    pub struct PrecompileFlags: u32 {
        const EXIT_TO_NEAR        = 0b01;
        const EXIT_TO_ETHEREUM    = 0b10;
    }
}
```
