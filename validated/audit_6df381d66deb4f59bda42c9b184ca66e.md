### Title
`calculate_attached_gas` Silently Returns Zero Gas, Causing `storage_deposit` Attached Deposit to Be Stranded in Engine Contract — (`engine/src/contract_methods/connector.rs`)

---

### Summary

`calculate_attached_gas` can return `NearGas::new(0)` when the caller attaches insufficient prepaid gas. All three storage functions (`storage_deposit`, `storage_unregister`, `storage_withdraw`) forward this zero-gas value to the connector promise via `return_promise`. For `storage_deposit` specifically, the user's full attached NEAR deposit is forwarded with that promise. When the connector-side `engine_storage_deposit` receipt executes with 0 gas it immediately fails; NEAR Protocol refunds the attached deposit to the engine contract (the receipt's `predecessor_id`), not to the original user. No failure callback exists to re-route the refund, so the user's deposit is stranded in the engine contract's balance.

---

### Finding Description

**`calculate_attached_gas` (line 587–596):**

```rust
// TODO: Return `Result` with an error about lacking of gas instead.
fn calculate_attached_gas<E: Env>(env: &E) -> NearGas {
    let required_gas = env.used_gas().saturating_add(GAS_FOR_PROMISE_CREATION);

    if required_gas >= env.prepaid_gas() {
        NearGas::new(0)          // ← silently returns zero
    } else {
        env.prepaid_gas() - required_gas
    }
}
``` [1](#0-0) 

The TODO comment is the developers' own acknowledgement that this path is wrong and should return an error instead.

`GAS_FOR_PROMISE_CREATION` is 2 TGas: [2](#0-1) 

**`storage_deposit` (line 288–309)** passes the user's full attached deposit to `return_promise`: [3](#0-2) 

**`return_promise` (line 598–617)** builds the connector promise with `attached_gas: calculate_attached_gas(env)` and no failure callback: [4](#0-3) 

When `calculate_attached_gas` returns 0, the `PromiseCreateArgs` carries `attached_gas = 0` and `attached_balance = user_deposit`. NEAR Protocol schedules the receipt. When the connector tries to execute `engine_storage_deposit` with 0 gas, it immediately fails with gas exhaustion. NEAR Protocol then issues a refund receipt for the attached deposit back to the receipt's `predecessor_id` — the engine contract — not the original transaction signer. The engine contract has no handler for this implicit refund, so the NEAR tokens are credited to the engine contract's account balance and are inaccessible to the user without admin intervention.

---

### Impact Explanation

- **`storage_deposit`**: User's attached NEAR deposit (intended as storage stake, typically ≥ 1.25 mNEAR) is stranded in the engine contract. The user's storage balance on the connector is never updated, so subsequent `ft_transfer` calls that require registered storage will fail.
- **`storage_unregister` / `storage_withdraw`**: Only 1 yoctoNEAR is forwarded, so the monetary loss is negligible, but the operation silently fails.

Impact classification: **High — Temporary freezing of funds** (user's deposit is inaccessible without admin/governance recovery of the engine contract's balance).

---

### Likelihood Explanation

A user (or a buggy SDK/wallet) must attach a `prepaid_gas` value low enough that, by the time `calculate_attached_gas` is called, fewer than 2 TGas remain. Because NEAR gas consumption is deterministic, an attacker can measure the exact gas used by the function body and craft a transaction with `prepaid_gas = used_gas_at_calculate_point + 1 TGas` (i.e., less than `GAS_FOR_PROMISE_CREATION = 2 TGas` remaining). Standard wallets attach 300 TGas, so accidental triggering is unlikely, but deliberate self-harm or a buggy integration is a realistic path. The TODO comment confirms the developers already identified this as a defect.

---

### Recommendation

Replace the silent zero-return with an explicit guard that returns an error before any state-mutating or deposit-forwarding work is done:

```rust
fn calculate_attached_gas<E: Env>(env: &E) -> Result<NearGas, ContractError> {
    let required_gas = env.used_gas().saturating_add(GAS_FOR_PROMISE_CREATION);
    if required_gas >= env.prepaid_gas() {
        Err(errors::ERR_NOT_ENOUGH_GAS.into())
    } else {
        Ok(env.prepaid_gas() - required_gas)
    }
}
```

All callers (`storage_deposit`, `storage_unregister`, `storage_withdraw`, `ft_transfer`, `ft_transfer_call`, `withdraw`, `ft_metadata`, `storage_balance_of`, `ft_balance_of`, `ft_total_eth_supply_on_near`) must propagate this error with `?`. For `storage_deposit` specifically, the attached deposit must be refunded to the caller before returning the error (or the function must be made `#[payable]` with an explicit refund action).

---

### Proof of Concept

```rust
// Pseudocode unit test (deterministic, no mainnet/testnet)
let used_gas_at_entry = measure_used_gas_for_storage_deposit_body(); // deterministic
let prepaid_gas = used_gas_at_entry + 1_000_000_000_000; // 1 TGas < GAS_FOR_PROMISE_CREATION (2 TGas)
let attached_deposit = 1_250_000_000_000_000_000_000; // 1.25 mNEAR

let env = MockEnv {
    prepaid_gas: NearGas::new(prepaid_gas),
    used_gas:    NearGas::new(used_gas_at_entry),
    attached_deposit,
    predecessor: "user.near",
};

let result_promise = storage_deposit(io, &env);

// Assert: promise was created with attached_gas == 0
assert_eq!(captured_promise.attached_gas, NearGas::new(0));
// Assert: promise carries the user's full deposit
assert_eq!(captured_promise.attached_balance, Yocto::new(attached_deposit));

// Simulate connector receipt failure (gas exhaustion)
// NEAR refunds deposit to engine contract (predecessor), not user
// Assert: user's storage balance on connector is unchanged
// Assert: engine contract balance increased by `attached_deposit`
// Assert: user cannot call ft_transfer (storage not registered)
```

### Citations

**File:** engine/src/contract_methods/connector.rs (L41-41)
```rust
const GAS_FOR_PROMISE_CREATION: NearGas = NearGas::new(2_000_000_000_000);
```

**File:** engine/src/contract_methods/connector.rs (L302-308)
```rust
    return_promise(
        io,
        env,
        "engine_storage_deposit",
        args,
        Yocto::new(env.attached_deposit()),
    )
```

**File:** engine/src/contract_methods/connector.rs (L587-596)
```rust
// TODO: Return `Result` with an error about lacking of gas instead.
fn calculate_attached_gas<E: Env>(env: &E) -> NearGas {
    let required_gas = env.used_gas().saturating_add(GAS_FOR_PROMISE_CREATION);

    if required_gas >= env.prepaid_gas() {
        NearGas::new(0)
    } else {
        env.prepaid_gas() - required_gas
    }
}
```

**File:** engine/src/contract_methods/connector.rs (L605-614)
```rust
    let promise_args = PromiseCreateArgs {
        target_account_id: get_connector_account_id(&io)?,
        method: method.to_string(),
        args,
        attached_balance: deposit,
        attached_gas: calculate_attached_gas(env),
    };
    let promise_id = io.promise_create_call(&promise_args);

    io.promise_return(promise_id);
```
