### Title
Excess attached deposit is not refunded when `AddressRegistrar::register()` succeeds, permanently trapping user overpayments - (File: `runtime/near-wallet-contract/implementation/address-registrar/src/lib.rs`)

### Summary
The `register()` method of the `AddressRegistrar` contract only validates that the attached deposit is *at least* the required storage cost (`given_deposit < required_deposit` check), but never refunds the excess when a caller overpays and the registration succeeds. This mirrors the reported Cally bug class where `buyOption()` accepted `msg.value >= premium` instead of requiring an exact match, silently absorbing user overpayments.

### Finding Description
In `register()`, the contract computes `required_deposit` from the storage bytes needed and reads `given_deposit` via `env::attached_deposit()`. It panics only if `given_deposit < required_deposit`, allowing any `given_deposit >= required_deposit` to pass: [1](#0-0) 

When the address slot is `Entry::Vacant` (the normal successful registration path), the code inserts the account id and returns the encoded address, but it never transfers back any deposit in excess of `required_deposit`: [2](#0-1) 

By contrast, the `Entry::Occupied` (collision) branch explicitly refunds the *entire* `given_deposit` back to the predecessor because no storage was consumed: [3](#0-2) 

This asymmetry shows the developers understood refund semantics for the failure path, but omitted the analogous logic for the success path — any deposit strictly greater than `required_deposit` on a successful, non-colliding `register()` call is silently retained by the contract's account balance with no code path to return it to the caller.

### Impact Explanation
Any unprivileged account calling `register()` (a `#[payable]` method reachable via an ordinary `FunctionCall` action with an attached deposit) that overpays — e.g., due to a wallet/frontend estimating deposit generously, or a caller intentionally rounding up — permanently loses the excess NEAR into the `AddressRegistrar` contract's account balance. There is no method exposed on the contract to withdraw or reclaim this excess, so the funds are effectively stuck/lost to the calling user, i.e., an unauthorized balance change from the caller's perspective with no path to recovery. This matches the report's bug class of "excess funds paid... transferred to [and retained by] the other party."

### Likelihood Explanation
Likelihood is moderate: it requires a caller to attach more than the exact storage-cost deposit, which can easily happen in practice since callers estimating storage cost for a variable-length `account_id` may round up or use a fixed generous deposit rather than computing the exact byte cost. No malicious actor coordination or special privileges are needed — a normal user transaction triggers the loss.

### Recommendation
In the `Entry::Vacant` success branch of `register()`, compute the excess deposit (`given_deposit.saturating_sub(required_deposit)`) and, if nonzero, issue a `promise_batch_action_transfer` refund to `env::predecessor_account_id()`, mirroring the refund logic already implemented in the `Entry::Occupied` branch. Alternatively, tighten the initial check to require `given_deposit == required_deposit` and reject/panic otherwise, consistent with the mitigation recommended in the referenced report.

### Proof of Concept
1. An unprivileged account calls `register(account_id)` with `env::attached_deposit()` set to, say, `required_deposit + 1_000_000` yoctoNEAR.
2. Since `given_deposit >= required_deposit`, the check at lines 54-61 passes.
3. Because the address slot for this `account_id` is vacant, execution takes the `Entry::Vacant` branch (lines 65-72), inserts the mapping, and returns `Some(address)` — without emitting any transfer action to refund the extra `1_000_000` yoctoNEAR.
4. The excess deposit remains part of the `AddressRegistrar` contract account's balance indefinitely, with no method in the contract to return it to the original caller.

### Citations

**File:** runtime/near-wallet-contract/implementation/address-registrar/src/lib.rs (L48-61)
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
```

**File:** runtime/near-wallet-contract/implementation/address-registrar/src/lib.rs (L65-72)
```rust
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
