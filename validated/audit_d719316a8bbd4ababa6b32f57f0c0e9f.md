### Title
XCC Router Creation Condition Remains True Across Multiple Transactions Due to Async Version Update, Causing Permanent Loss of User wNEAR Funds - (File: engine/src/xcc.rs, engine-precompiles/src/xcc.rs)

---

### Summary

The XCC precompile charges users an extra `STORAGE_AMOUNT` (2 NEAR) in wNEAR EVM tokens when their router sub-account does not yet exist. This check reads `get_code_version_of_address` from storage. However, the version is only written to storage after the async `factory_update_address_version` callback completes — which happens in a later NEAR block. If a user submits two XCC transactions before the first callback completes, both transactions observe `None` for the router version, both charge `STORAGE_AMOUNT` from the user's wNEAR EVM balance, and the second deploy batch fails (account already exists). The second `STORAGE_AMOUNT` is permanently stranded in the engine's implicit address with no refund path.

---

### Finding Description

**Step 1 — Charge in the precompile (synchronous, within EVM execution)**

In `engine-precompiles/src/xcc.rs`, the precompile reads the router version and charges the user:

```rust
let required_near =
    match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
        None => attached_near + state::STORAGE_AMOUNT,   // ← charged if no router exists
        Some(_) => attached_near,
    };
if required_near != ZERO_YOCTO {
    // transferFrom user → engine implicit address (wNEAR EVM balance debited NOW)
    handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
}
```

The user's wNEAR EVM balance is debited immediately and irrevocably during EVM execution.

**Step 2 — Deploy batch scheduled (async, executes in a later NEAR block)**

In `engine/src/xcc.rs`, `handle_precompile_promise` reads the same storage key and schedules the router creation:

```rust
let sender_code_version = get_code_version_of_address(io, &sender);
let deploy_needed = AddressVersionStatus::new(io, latest_code_version, sender_code_version);
// If DeployNeeded { create_needed: true }:
//   → promise_create_batch(CreateAccount + Transfer + DeployContract + Initialize)
//   → promise_attach_callback(..., "factory_update_address_version")
//   → promise_attach_callback(..., "withdraw_wnear_to_router")
//   → promise_attach_callback(..., actual user call)
```

**Step 3 — Version update is async**

`factory_update_address_version` in `engine/src/contract_methods/xcc.rs` is the only place that writes the version to storage:

```rust
xcc::set_code_version_of_address(&mut io, &args.address, args.version);
```

This executes in a later NEAR block as a callback. Until it completes, `get_code_version_of_address` still returns `None` for this address.

**Step 4 — Second transaction in the same window**

If the user submits TX2 before TX1's callback chain completes:
- TX2's precompile sees `None` → charges `STORAGE_AMOUNT` again from wNEAR EVM balance
- TX2's deploy batch tries `CreateAccount` on an already-existing account → **batch fails**
- TX2's `factory_update_address_version` receives a failed promise → returns `ERR_ROUTER_DEPLOY_FAILED`
- TX2's `withdraw_wnear_to_router` checks `promise_result_check()` → returns `ERR_CALLBACK_OF_FAILED_PROMISE`
- The wNEAR tokens transferred to the engine's implicit address in TX2's EVM execution are **never converted and never refunded**

---

### Impact Explanation

The user permanently loses `STORAGE_AMOUNT` (2 NEAR worth of wNEAR EVM tokens) per duplicate transaction submitted in the window between TX1's EVM execution and TX1's `factory_update_address_version` callback. The tokens are stranded in the engine's implicit EVM address with no on-chain recovery path for the user. This is a direct, permanent loss of user funds.

**Impact: High — Permanent freezing / theft of user funds (wNEAR tokens).**

---

### Likelihood Explanation

A user submitting two XCC transactions in rapid succession (e.g., two consecutive nonces in the same NEAR block, or across two blocks before the callback from the first completes) will trigger this. NEAR block times are ~1 second and callbacks execute in subsequent blocks, so the vulnerable window spans at least one full block. This is a realistic scenario for any user who retries or batches XCC calls. No attacker cooperation is required — the user's own normal usage pattern is sufficient.

**Likelihood: Medium.**

---

### Recommendation

Mirror the fix applied in the StakeDAO report: tighten the condition so the "creation needed" path is only entered once. Specifically, before charging `STORAGE_AMOUNT` in the precompile and before scheduling the deploy batch in `handle_precompile_promise`, introduce a **pending-creation flag** written to storage at the start of TX1 and cleared by the `factory_update_address_version` callback. Alternatively, treat a stored pending flag as equivalent to `Some(_)` in `get_code_version_of_address`, so subsequent transactions skip the extra charge until the callback confirms or denies the creation.

A simpler mitigation: in the precompile, if `get_code_version_of_address` returns `None` but a pending-creation sentinel key exists for this address, treat it as `Some(_)` and do not charge `STORAGE_AMOUNT`.

---

### Proof of Concept

1. User `A` has no XCC router deployed. `get_code_version_of_address(A) == None`.
2. User submits **TX1** (XCC call): precompile debits `STORAGE_AMOUNT + attached_near` from `A`'s wNEAR EVM balance. Deploy batch is scheduled.
3. Before TX1's `factory_update_address_version` callback executes (i.e., within the same or next NEAR block), user submits **TX2** (another XCC call): precompile again sees `None`, debits `STORAGE_AMOUNT + attached_near` again.
4. TX1's deploy batch executes: router account created successfully. `factory_update_address_version` writes version. `withdraw_wnear_to_router` converts wNEAR → NEAR. User call executes.
5. TX2's deploy batch executes: `CreateAccount` fails (account exists). `factory_update_address_version` receives failed result → `ERR_ROUTER_DEPLOY_FAILED`. `withdraw_wnear_to_router` receives failed result → `ERR_CALLBACK_OF_FAILED_PROMISE`. User call never executes.
6. The `STORAGE_AMOUNT` wNEAR debited in step 3 remains in the engine's implicit address. User has lost 2 NEAR permanently.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** engine-precompiles/src/xcc.rs (L177-182)
```rust
        let required_near =
            match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
                // If there is no deployed version of the router contract then we need to charge for storage staking
                None => attached_near + state::STORAGE_AMOUNT,
                Some(_) => attached_near,
            };
```

**File:** engine/src/xcc.rs (L206-208)
```rust
    let latest_code_version = get_latest_code_version(io);
    let sender_code_version = get_code_version_of_address(io, &sender);
    let deploy_needed = AddressVersionStatus::new(io, latest_code_version, sender_code_version);
```

**File:** engine/src/xcc.rs (L376-380)
```rust
pub fn set_code_version_of_address<I: IO>(io: &mut I, address: &Address, version: CodeVersion) {
    let key = storage::bytes_to_key(KeyPrefix::CrossContractCall, address.as_bytes());
    let value_bytes = version.0.to_le_bytes();
    io.write_storage(&key, &value_bytes);
}
```

**File:** engine/src/xcc.rs (L453-475)
```rust
impl AddressVersionStatus {
    fn new<I: IO>(
        io: &I,
        latest_code_version: CodeVersion,
        target_code_version: Option<CodeVersion>,
    ) -> Self {
        let first_upgradable_version =
            get_first_upgradable_version(io).unwrap_or(CodeVersion::ZERO);
        match target_code_version {
            None => Self::DeployNeeded {
                create_needed: true,
            },
            Some(version) if version < first_upgradable_version => {
                // It is impossible to upgrade the initial XCC routers because
                // they lack the upgrade method.
                Self::UpToDate
            }
            Some(version) if version < latest_code_version => Self::DeployNeeded {
                create_needed: false,
            },
            Some(_version) => Self::UpToDate,
        }
    }
```

**File:** engine/src/contract_methods/xcc.rs (L80-99)
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
```
