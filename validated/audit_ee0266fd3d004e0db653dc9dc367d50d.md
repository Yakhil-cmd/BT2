### Title
Gateway Admits Invoke Transactions with Unverified Signatures via `skip_stateful_validations` Deploy-Account UX Bypass - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the account's `__validate__` entry point (the only place where the transaction signature is verified) for any invoke transaction with `nonce == 1` targeting an account whose on-chain nonce is `0` and which has any transaction present in the mempool. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit an invoke transaction for the victim's address carrying an arbitrary or empty signature. The gateway admits this transaction without any cryptographic check, inserting it into the mempool alongside the victim's legitimate first invoke.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks` after the nonce and resource-bound checks pass:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
// lines 310-312
let strict_nonce_check = false;
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

With `validate = false`, `StatefulValidator::perform_validations` returns immediately without calling `__validate__`:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs  lines 79-81
if !tx.execution_flags.validate {
    return Ok(());
}
``` [3](#0-2) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce ordering and fee escalation — it never inspects the signature:

```rust
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
``` [4](#0-3) 

`account_tx_in_pool_or_recent_block` returns `true` as soon as the victim's `deploy_account` lands in the mempool pool:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [5](#0-4) 

**Attack path:**

1. Victim broadcasts `deploy_account` (nonce 0) → enters mempool.
2. Attacker observes victim's address in the mempool via `account_tx_in_pool_or_recent_block`.
3. Attacker submits `Invoke V3` with `sender_address = victim`, `nonce = 1`, arbitrary calldata, and a random/empty signature.
4. Gateway stateless checks pass (signature length ≤ max, resource bounds non-zero).
5. `validate_nonce` passes (nonce 1 is within `max_allowed_nonce_gap` of account nonce 0).
6. `skip_stateful_validations` returns `true` → `__validate__` is never called → no signature check.
7. Attacker's transaction is admitted to the mempool.
8. If the attacker sets a higher tip than the victim's legitimate invoke, the mempool's fee-escalation logic evicts the victim's invoke (`validate_fee_escalation` / `remove_replaced_tx`).
9. At execution time the batcher runs `__validate__` with `validate = true` (default for sequencing), the invalid signature causes the invoke to revert, but the victim's legitimate invoke has already been evicted.

### Impact Explanation

The gateway admits an invoke transaction whose signature has never been verified. This breaks the invariant that every transaction in the mempool has passed account-level authentication. Concretely:

- **Mempool pollution**: An attacker can inject arbitrarily many signature-less invokes for any account that has a pending `deploy_account`, consuming mempool capacity.
- **Griefing / first-invoke blocking**: By submitting with a higher tip, the attacker can evict the victim's legitimate first invoke via fee escalation. The attacker's transaction then fails at execution (invalid signature, no nonce increment), but the victim's invoke is gone and must be resubmitted — potentially after the deploy-account window has closed or the victim's UX flow is broken.

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The trigger is fully unprivileged and requires only:
- Monitoring the public mempool for `deploy_account` transactions (any node can do this).
- Submitting a single crafted invoke with the victim's address, nonce 1, and any signature.

No special access, keys, or prior relationship with the victim is needed. The window is open from the moment the victim's `deploy_account` enters the mempool until the block containing it is committed.

### Recommendation

Before skipping the blockifier `__validate__` call, perform a lightweight off-chain signature pre-check. Specifically, the gateway should verify that the invoke transaction's signature is structurally valid against the account's expected public key (derivable from the `deploy_account` constructor calldata already in the mempool) before setting `skip_validate = true`. Alternatively, restrict the skip to cases where the gateway can cryptographically confirm the invoke originates from the same submitter as the `deploy_account` (e.g., by requiring both transactions to be submitted atomically in the same gateway request and verifying the signature against the to-be-deployed class's `__validate__` ABI off-chain).

### Proof of Concept

```
1. Victim calls gateway: POST /add_transaction with deploy_account_v3
   { class_hash: C, salt: S, constructor_calldata: [...], nonce: 0, signature: [valid_sig] }
   → Gateway admits it; mempool now contains victim_address.

2. Attacker calls gateway: POST /add_transaction with invoke_v3
   { sender_address: victim_address, nonce: 1, calldata: [drain_calldata],
     signature: [0x0, 0x0],   ← completely invalid
     resource_bounds: { l2_gas: { max_amount: X, max_price_per_unit: Y } },
     tip: victim_tip + 1 }    ← higher tip to win fee escalation

3. Gateway stateless validator:
   - validate_contract_address: victim_address is valid ✓
   - validate_resource_bounds: non-zero ✓
   - validate_tx_size: signature length 2 ≤ max ✓

4. Gateway stateful validator:
   - get_nonce_from_state(victim_address) → 0
   - validate_nonce: 1 ≤ 0 + max_allowed_nonce_gap ✓
   - validate_by_mempool: no duplicate, fee escalation wins ✓
   - skip_stateful_validations: nonce==1 && account_nonce==0 &&
       account_tx_in_pool_or_recent_block(victim_address)==true → returns true
   - run_validate_entry_point: execution_flags.validate = false → __validate__ NOT called ✓

5. Attacker's invoke is admitted to mempool; victim's legitimate invoke is evicted
   (higher tip → fee escalation removes victim's tx).

6. Batcher produces block:
   - deploy_account executes → victim's contract deployed ✓
   - attacker's invoke executes → __validate__ called → signature [0x0,0x0] fails → REVERT
   - victim's invoke is gone from mempool; victim must resubmit.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-461)
```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        // check if the transaction nonce is 1, meaning it is post deploy_account, and the
        // account nonce is zero, meaning the account was not deployed yet.
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            let account_address = tx.sender_address();
            debug!("Checking if deploy_account transaction exists for account {account_address}.");
            // We verify that a deploy_account transaction exists for this account. It is sufficient
            // to check if the account exists in the mempool since it means that either it has a
            // deploy_account transaction or transactions with future nonces that passed
            // validations.
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
                .inspect(|exists| {
                    if *exists {
                        debug!("Found deploy_account transaction for account {account_address}.");
                    } else {
                        debug!(
                            "No deploy_account transaction found for account {account_address}."
                        );
                    }
                });
        }
    }

    Ok(false)
}
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

        Ok(())
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
