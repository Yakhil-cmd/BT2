Based on my investigation, `AddressRegistrar::register()` in `runtime/near-wallet-contract/implementation/address-registrar/src/lib.rs` contains a genuine analog of this bug class.

### Title
Excess Attached Deposit Is Not Refunded on Successful Registration in `AddressRegistrar::register` - (File: `runtime/near-wallet-contract/implementation/address-registrar/src/lib.rs`)

### Summary
The `#[payable]` `register()` method computes a `required_deposit` for the storage cost of the new entry and only checks `given_deposit >= required_deposit`, panicking on underpayment. On the success path (`Entry::Vacant`), it stores the mapping and returns the address, but never computes or refunds `given_deposit - required_deposit`. Only the failure path (`Entry::Occupied`, address collision) refunds the *entire* deposit.

### Finding Description
`register()` computes `required_deposit` from `bytes_to_store` and `storage_byte_cost()`, then validates `given_deposit >= required_deposit`, but if the check passes and the entry is vacant, the function inserts the mapping and returns `Some(address)` without ever transferring back the difference between `given_deposit` and `required_deposit`. [1](#0-0) 

This mirrors the reported Solidity pattern exactly: a `>=` payment check followed by irreversible retention of any excess. The only refund path in this contract is for the collision (failure) case, which refunds the deposit in full via an explicit `Transfer` promise: [2](#0-1) 

This is unlike nearcore's native protocol-level deposit refund mechanism (used for `FunctionCall`/`Transfer` action receipts that fail), which automatically refunds the full deposit to the predecessor when a receipt fails, and is well tested and documented: [3](#0-2) [4](#0-3) 

The `AddressRegistrar` contract sits outside that native refund mechanism because it is application-level Rust/near-sdk code (a normal contract, not core runtime logic), so any excess deposit it accepts on a successful call is simply added to the contract's own account balance with no code path returning it to the caller.

### Impact Explanation
Any account (including relayers on behalf of end users via the wallet-contract's `register` flow, or any direct unprivileged caller) that attaches more NEAR than the exact computed storage cost when calling `register()` permanently loses the excess to the registrar contract's balance. There is no withdrawal/refund mechanism for the excess in the success path, so overpaying users cannot recover their funds. This is a straightforward, unauthorized-in-intent balance loss for the caller reachable directly by any unprivileged transaction/contract call to `AddressRegistrar::register`.

### Likelihood Explanation
Overpayment is easy to trigger: `required_deposit` depends on `storage_byte_cost()` and the exact byte length of the `account_id`, both of which callers may not compute precisely, and any client/relayer that attaches a conservative/rounded deposit (e.g., a fixed buffer) to guarantee passing the `>=` check will systematically overpay on every successful registration. Since the contract is part of the `near-wallet-contract` implementation intended for production use, this is a realistic, easily reproducible occurrence rather than an edge case.

### Recommendation
In the `Entry::Vacant` success branch of `register()`, compute `excess = given_deposit - required_deposit` and, if greater than zero, issue a `promise_batch_action_transfer` back to `env::predecessor_account_id()` for the excess amount, analogous to what is already done in the `Entry::Occupied` branch, following the Checks-Effects-Interactions pattern (perform the refund transfer after the state (`entry.insert`) is finalized).

### Proof of Concept
1. Compute `required_deposit` for a target `account_id` (e.g., `20 + len(account_id)` bytes times `storage_byte_cost()`).
2. Call `register(account_id)` attaching `given_deposit = required_deposit + X` for some `X > 0`, where `address` is not already registered.
3. The `given_deposit >= required_deposit` check passes; the `Entry::Vacant` branch executes, inserting the mapping and returning `Some(address)`. [5](#0-4) 
4. No transfer back to the caller occurs; the contract's account balance now includes the caller's excess `X` yoctoNEAR permanently, unlike the collision path which refunds the caller in full.

### Citations

**File:** runtime/near-wallet-contract/implementation/address-registrar/src/lib.rs (L48-72)
```rust
        // Must store the address and the account id
        let bytes_to_store = 20 + (account_id.len() as u128);
        let required_deposit =
            NearToken::from_yoctonear(env::storage_byte_cost().as_yoctonear() * bytes_to_store);
        let given_deposit = env::attached_deposit();
        // The caller must pay for the storage cost of registering.
        if given_deposit < required_deposit {
            let message = format!(
                "Insufficient deposit to cover storage cost. Given={} Expected={}",
                given_deposit.as_yoctonear(),
                required_deposit.as_yoctonear(),
            );
            env::panic_str(&message);
        }

        let address = account_id_to_address(&account_id);

        match self.addresses.entry(address) {
            Entry::Vacant(entry) => {
                let address = format!("0x{}", hex::encode(address));
                let log_message = format!("Added entry {} -> {}", address, account_id);
                entry.insert(account_id);
                env::log_str(&log_message);
                Some(address)
            }
```

**File:** runtime/near-wallet-contract/implementation/address-registrar/src/lib.rs (L73-85)
```rust
            Entry::Occupied(entry) => {
                let log_message = format!(
                    "Address collision between {} and {}. Keeping the former.",
                    entry.get(),
                    account_id
                );
                env::log_str(&log_message);
                // Transfer the deposit back to the caller since no storage was updated.
                let refund_promise = env::promise_batch_create(&env::predecessor_account_id());
                env::promise_batch_action_transfer(refund_promise, given_deposit);
                None
            }
        }
```

**File:** docs/RuntimeSpec/Refunds.md (L15-18)
```markdown
## Deposit Refunds

Deposit refunds are generated when an action receipt fails to execute. All attached deposit amounts are summed together and
sent as a refund to a `predecessor_id` (because only the predecessor can attach deposits).
```

**File:** runtime/runtime/src/lib.rs (L1269-1274)
```rust
        if deposit_refund > Balance::ZERO {
            result.new_receipts.push(Receipt::new_balance_refund(
                receipt.balance_refund_receiver(),
                deposit_refund,
            ));
        }
```
