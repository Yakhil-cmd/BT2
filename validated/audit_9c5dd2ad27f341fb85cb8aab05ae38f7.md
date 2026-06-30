### Title
XCC Precompile Overcharges `STORAGE_AMOUNT` wNEAR on Concurrent First-Time Router Creation Due to Stale `code_version_of_address` Read — (`engine-precompiles/src/xcc.rs`, `engine/src/xcc.rs`)

---

### Summary

The XCC precompile reads `code_version_of_address` synchronously to decide whether to charge the user `STORAGE_AMOUNT` (2 NEAR) in wNEAR for router account creation. However, this storage key is only written in the asynchronous callback `factory_update_address_version`, which executes after the full promise chain settles. If the same EVM address submits two XCC transactions in the same NEAR block before the callback runs, both transactions see `code_version = None`, both charge the user 2 NEAR in wNEAR, but only one router creation succeeds. The second wNEAR payment is permanently stranded in the engine's implicit EVM address with no refund path.

---

### Finding Description

**Step 1 — Synchronous balance check in the precompile:**

In `engine-precompiles/src/xcc.rs`, `run_with_handle` reads the router version for the sender:

```rust
let required_near =
    match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
        None => attached_near + state::STORAGE_AMOUNT,
        Some(_) => attached_near,
    };
```

When `None`, it immediately executes an EVM-level `transferFrom` to move `required_near` wNEAR from the sender to the engine's implicit address:

```rust
let (exit_reason, return_value) =
    handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
``` [1](#0-0) 

**Step 2 — Router creation is asynchronous; version is written only in the callback:**

In `engine/src/xcc.rs`, `handle_precompile_promise` also reads `get_code_version_of_address` and, when `None`, schedules a NEAR batch to create the router account. It then attaches `factory_update_address_version` as a callback:

```rust
let callback = PromiseCreateArgs {
    target_account_id: current_account_id.clone(),
    method: "factory_update_address_version".into(),
    ...
};
Some(handler.promise_attach_callback(promise_id, &callback))
``` [2](#0-1) 

The actual write to storage only happens inside `factory_update_address_version`:

```rust
xcc::set_code_version_of_address(&mut io, &args.address, args.version);
``` [3](#0-2) 

**Step 3 — No eager write before the async chain; stale state persists across transactions in the same block:**

Between the moment the first XCC transaction is processed and the moment `factory_update_address_version` settles (which is in a future NEAR block), `get_code_version_of_address` still returns `None` for that sender address. Any second XCC transaction submitted in the same block reads the same stale `None` and repeats the full `STORAGE_AMOUNT` charge. [4](#0-3) 

**Step 4 — The second router creation fails; the wNEAR is stranded:**

In `engine/src/contract_methods/xcc.rs`, `withdraw_wnear_to_router` is a callback of the router-creation batch. When the second batch fails (because the NEAR account already exists), this callback aborts:

```rust
if matches!(handler.promise_result_check(), Some(false)) {
    return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
}
``` [5](#0-4) 

The wNEAR that was already transferred to the engine's implicit EVM address in Step 1 is never unwrapped or returned. There is no refund branch for this failure path in the XCC precompile (unlike the `ExitToNear` precompile which has an `error_refund` feature). [6](#0-5) 

---

### Impact Explanation

`STORAGE_AMOUNT` is 2 NEAR (2 × 10²⁴ yoctoNEAR). [7](#0-6) 

When the second transaction's router creation fails, the 2 NEAR worth of wNEAR transferred to the engine's implicit EVM address (`near_account_to_evm_address(engine_account_id)`) has no recovery path. The engine's implicit address is not controlled by any private key and there is no admin function to sweep stranded wNEAR from it. The user's funds are permanently frozen.

**Impact: High — Permanent freezing of user funds.**

---

### Likelihood Explanation

The window is open for the entire duration between a user's first XCC transaction being processed and the `factory_update_address_version` callback settling (at minimum one NEAR block, typically 1–2 seconds). Any of the following realistic scenarios triggers the loss:

- A user or dApp submits two XCC transactions in the same NEAR block (e.g., batched relayer submission, retry on apparent failure, or parallel dApp calls).
- A relayer processes multiple pending EVM transactions from the same address in one block.

The user must have sufficient wNEAR approved to the XCC precompile for both charges to succeed. This is a realistic condition for active XCC users.

**Likelihood: Medium.**

---

### Recommendation

Write `code_version_of_address` eagerly (with a sentinel "pending" value) at the time the XCC precompile charges the user, before the async promise chain is scheduled. The `factory_update_address_version` callback can then overwrite it with the final version. This prevents any subsequent transaction in the same block from seeing `None` and re-charging the user.

Alternatively, add a refund path in `handle_precompile_promise` analogous to the `error_refund` mechanism in the `ExitToNear` precompile: if the router-creation batch fails, return the stranded wNEAR to the sender's EVM address.

---

### Proof of Concept

1. Alice has 4+ NEAR worth of wNEAR in her EVM address and has approved the XCC precompile to spend it.
2. Alice has no existing XCC router (`get_code_version_of_address` returns `None`).
3. Alice (or a relayer on her behalf) submits two EVM transactions calling the XCC precompile in the same NEAR block.
4. **TX1** is processed: `code_version = None` → 2 NEAR wNEAR transferred to engine implicit address → router creation batch scheduled.
5. **TX2** is processed in the same block: `code_version` is still `None` (callback has not run) → another 2 NEAR wNEAR transferred to engine implicit address → second router creation batch scheduled.
6. TX1's router creation succeeds; `factory_update_address_version` sets `code_version` for Alice.
7. TX2's router creation fails (`CreateAccount` on an already-existing account). `withdraw_wnear_to_router` aborts with `ERR_CALLBACK_OF_FAILED_PROMISE`.
8. Alice has lost 2 NEAR in wNEAR, permanently stranded in the engine's implicit EVM address with no recovery mechanism. [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** engine-precompiles/src/xcc.rs (L177-216)
```rust
        let required_near =
            match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
                // If there is no deployed version of the router contract then we need to charge for storage staking
                None => attached_near + state::STORAGE_AMOUNT,
                Some(_) => attached_near,
            };
        // if some NEAR payment is needed, transfer it from the caller to the engine's implicit address
        if required_near != ZERO_YOCTO {
            let engine_implicit_address = aurora_engine_sdk::types::near_account_to_evm_address(
                self.engine_account_id.as_bytes(),
            );
            let tx_data = transfer_from_args(
                sender.0.into(),
                engine_implicit_address.raw().0.into(),
                required_near.as_u128().into(),
            );
            let wnear_address = state::get_wnear_address(&self.io);
            let context = aurora_evm::Context {
                address: wnear_address.raw(),
                caller: cross_contract_call::ADDRESS.raw(),
                apparent_value: U256::zero(),
            };
            let (exit_reason, return_value) =
                handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
            match exit_reason {
                // Transfer successful, nothing to do
                aurora_evm::ExitReason::Succeed(_) => (),
                aurora_evm::ExitReason::Revert(r) => {
                    return Err(PrecompileFailure::Revert {
                        exit_status: r,
                        output: return_value,
                    });
                }
                aurora_evm::ExitReason::Error(e) => {
                    return Err(PrecompileFailure::Error { exit_status: e });
                }
                aurora_evm::ExitReason::Fatal(f) => {
                    return Err(PrecompileFailure::Fatal { exit_status: f });
                }
            }
```

**File:** engine-precompiles/src/xcc.rs (L254-255)
```rust
    /// Amount of NEAR needed to cover storage for a router contract.
    pub const STORAGE_AMOUNT: Yocto = Yocto::new(2_000_000_000_000_000_000_000_000);
```

**File:** engine/src/xcc.rs (L206-208)
```rust
    let latest_code_version = get_latest_code_version(io);
    let sender_code_version = get_code_version_of_address(io, &sender);
    let deploy_needed = AddressVersionStatus::new(io, latest_code_version, sender_code_version);
```

**File:** engine/src/xcc.rs (L226-229)
```rust
            if *create_needed {
                promise_actions.push(PromiseAction::CreateAccount);
                promise_actions.push(PromiseAction::Transfer {
                    amount: STORAGE_AMOUNT,
```

**File:** engine/src/xcc.rs (L263-279)
```rust
            // Add a callback here to update the version of the account
            let args = AddressVersionUpdateArgs {
                address: sender,
                version: latest_code_version,
            };
            let callback = PromiseCreateArgs {
                target_account_id: current_account_id.clone(),
                method: "factory_update_address_version".into(),
                args: borsh::to_vec(&args).unwrap(),
                attached_balance: ZERO_YOCTO,
                attached_gas: VERSION_UPDATE_GAS,
            };

            // Safety: A call from the engine to the engine's `factory_update_address_version`
            // method is safe because that method only writes the specific router sub-account
            // metadata that has just been deployed above.
            Some(handler.promise_attach_callback(promise_id, &callback))
```

**File:** engine/src/contract_methods/xcc.rs (L33-35)
```rust
        if matches!(handler.promise_result_check(), Some(false)) {
            return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
        }
```

**File:** engine/src/contract_methods/xcc.rs (L80-100)
```rust
#[named]
pub fn factory_update_address_version<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &H,
) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        // The function is only set to be private, otherwise callback error will happen.
        env.assert_private_call()?;
        let check_deploy: Result<(), &[u8]> = match handler.promise_result_check() {
            Some(true) => Ok(()),
            Some(false) => Err(b"ERR_ROUTER_DEPLOY_FAILED"),
            None => Err(b"ERR_ROUTER_UPDATE_NOT_CALLBACK"),
        };
        check_deploy?;
        let args: xcc::AddressVersionUpdateArgs = io.read_input_borsh()?;
        xcc::set_code_version_of_address(&mut io, &args.address, args.version);
        Ok(())
    })
}
```
