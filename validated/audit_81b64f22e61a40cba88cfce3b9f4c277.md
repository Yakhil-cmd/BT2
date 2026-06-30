### Title
Non-Atomic Whitelist Activation and Entry Population Causes Temporary Freeze of All EVM Transactions - (File: `engine/src/contract_methods/silo/mod.rs`)

### Summary
In Aurora Engine's Silo mode, enabling a whitelist (`set_whitelist_status`) and populating it with entries (`add_entry_to_whitelist`) are separate NEAR contract calls requiring separate transactions. Between these two transactions, the whitelist is active but empty, causing every EVM transaction from every address to fail with `NotAllowed`, temporarily freezing all user funds on the Silo instance.

### Finding Description
The Silo whitelist system stores the enabled/disabled status of each whitelist kind independently from its member entries. Enabling a whitelist is done via `set_whitelist_status`, which writes only a status byte: [1](#0-0) 

Populating the whitelist with entries is done via a separate call, `add_entry_to_whitelist`: [2](#0-1) 

The access check for EVM transaction submission reads both the status and the entries independently: [3](#0-2) 

When the `Address` whitelist is enabled but empty, `!list.is_enabled() || list.is_exist(address)` evaluates to `false` for every address. This propagates through `is_allow_submit`: [4](#0-3) 

And into `assert_access`, which is called for every EVM transaction before gas is charged: [5](#0-4) 

The result is that every call to `submit` / `submit_with_args` returns `EngineErrorKind::NotAllowed` during the inter-transaction window. The public entrypoints for the two separate operations are: [6](#0-5) [7](#0-6) 

There is no single atomic function that enables a whitelist and populates it with entries in one NEAR transaction. The same split exists for the `Account`, `Admin`, and `EvmAdmin` kinds.

### Impact Explanation
**High — Temporary freezing of funds.** During the window between `set_whitelist_status(active=true)` and the subsequent `add_entry_to_whitelist` call(s), every EVM transaction on the Silo instance is rejected. Users cannot transfer ETH, move ERC-20 tokens, or interact with any on-chain contract. Their funds are inaccessible until the owner completes the second transaction. Because `assert_access` fires before `charge_gas`, no gas is consumed, but the freeze is real: no state-changing EVM call can succeed.

### Likelihood Explanation
The natural operator workflow is: (1) enable the whitelist to enforce access control, then (2) add the permitted addresses. Nothing in the protocol enforces the reverse order (add entries first while the whitelist is still disabled, then enable it). Any operator following the intuitive order creates this window. On NEAR, each NEAR transaction is a separate block-level event; the window spans at least one block (~1–2 seconds) and can be longer under network load or if the operator batches multiple `add_entry_to_whitelist` calls across several transactions.

### Recommendation
Introduce an atomic function such as `enable_whitelist_with_entries(kind, entries[])` that writes the status byte and all member entries within a single NEAR transaction. Alternatively, enforce in documentation and tooling that entries must be added **before** the whitelist is enabled, and consider adding a runtime guard that rejects `set_whitelist_status(active=true)` when the target whitelist has zero entries.

### Proof of Concept
```
// Step 1 — owner enables the Address whitelist (whitelist is now active, empty)
aurora.set_whitelist_status(WhitelistStatusArgs { kind: WhitelistKind::Address, active: true })

// Step 2 — any user submits an EVM transaction in the same or next block
aurora.submit(signed_eth_tx)
// → EngineErrorKind::NotAllowed  (funds frozen)

// Step 3 — owner adds the permitted address
aurora.add_entry_to_whitelist(WhitelistArgs::WhitelistAddressArgs { kind: Address, address: user_addr })

// Step 4 — user retries; now succeeds
aurora.submit(signed_eth_tx)  // → Ok
```

The freeze window is bounded only by NEAR block time and the number of `add_entry_to_whitelist` transactions the owner must send. For a Silo with many permitted addresses, the window can span multiple blocks. [8](#0-7) [9](#0-8)

### Citations

**File:** engine/src/contract_methods/silo/whitelist.rs (L40-47)
```rust
    /// Check if the whitelist is enabled.
    pub fn is_enabled(&self) -> bool {
        // White list is disabled by default. So return `false` if the key doesn't exist.
        let key = self.key(STATUS);
        self.io
            .read_storage(&key)
            .is_some_and(|value| value.to_vec() == [1])
    }
```

**File:** engine/src/contract_methods/silo/whitelist.rs (L77-85)
```rust
pub fn set_whitelist_status<I: IO + Copy>(io: &I, args: &WhitelistStatusArgs) {
    let mut list = Whitelist::init(io, args.kind);

    if args.active {
        list.enable();
    } else {
        list.disable();
    }
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L75-79)
```rust
/// Add an entry to a whitelist depending on a kind of list types in provided arguments.
pub fn add_entry_to_whitelist<I: IO + Copy>(io: &I, args: &WhitelistArgs) {
    let (kind, entry) = get_kind_and_entry(args);
    Whitelist::init(io, kind).add(entry);
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L97-100)
```rust
/// Set the given status of the provided whitelist.
pub fn set_whitelist_status<I: IO + Copy>(io: &I, args: &WhitelistStatusArgs) {
    whitelist::set_whitelist_status(io, args);
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L135-138)
```rust
/// Check if a user has the right to submit transactions.
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L155-163)
```rust
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}

fn is_account_allowed<I: IO + Copy>(io: &I, account: &AccountId) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Account);
    !list.is_enabled() || list.is_exist(account)
}
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

**File:** engine/src/lib.rs (L841-851)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn set_whitelist_status() {
        let io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: WhitelistStatusArgs = io.read_input_borsh().sdk_unwrap();
        silo::set_whitelist_status(&io, &args);
    }
```

**File:** engine/src/lib.rs (L886-896)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn add_entry_to_whitelist() {
        let io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: WhitelistArgs = io.read_input_borsh().sdk_unwrap();
        silo::add_entry_to_whitelist(&io, &args);
    }
```
