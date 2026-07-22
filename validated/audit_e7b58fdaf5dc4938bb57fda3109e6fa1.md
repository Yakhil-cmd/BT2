### Title
Signature Validation Bypass via Overly Broad `skip_stateful_validations` Mempool Check — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function skips the `__validate__` entry point for an Invoke transaction with `nonce=1` whenever `account_tx_in_pool_or_recent_block` returns `true` for the sender. That helper returns `true` for **any** transaction in the pool from that address — not only a `deploy_account` transaction. An adversary can therefore first submit a valid Invoke with `nonce=2` (which passes full `__validate__`), and then submit a second Invoke with `nonce=1` carrying an **invalid signature**. The gateway admits the second transaction to the mempool without ever calling `__validate__`, violating the invariant that every mempool-admitted transaction has passed account-level signature verification.

### Finding Description

**Root cause — `skip_stateful_validations`** (`crates/apollo_gateway/src/stateful_transaction_validator.rs`, lines 429–461):

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())   // ← too broad
                .await ...;
        }
    }
    Ok(false)
}
``` [1](#0-0) 

The comment claims "it means that either it has a deploy_account transaction **or** transactions with future nonces that passed validations." The second branch is the flaw: a valid `nonce=2` Invoke having passed `__validate__` says nothing about whether a `nonce=1` Invoke with a **different** transaction hash and a **different** (potentially forged) signature would pass `__validate__`.

**`account_tx_in_pool_or_recent_block` returns true for any pooled transaction:**

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)   // any tx, not deploy_account only
}
``` [2](#0-1) 

**`run_validate_entry_point` propagates the skip flag directly to `execution_flags.validate`:**

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

When `skip_validate=true`, `StatefulValidator::perform_validations` returns `Ok(())` immediately after `perform_pre_validation_stage` without ever calling `validate_tx` (the `__validate__` entry point):

```rust
tx.perform_pre_validation_stage(self.state(), &tx_context)?;
if !tx.execution_flags.validate {
    return Ok(());   // ← __validate__ never called
}
``` [4](#0-3) 

**`validate_by_mempool` does not check the signature** — `ValidationArgs` carries only `address`, `account_nonce`, `tx_hash`, `tx_nonce`, `tip`, and `max_l2_gas_price`:

```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
``` [5](#0-4) 

**Stateless validation** only checks signature *length*, not cryptographic validity:

```rust
fn validate_tx_signature_size(&self, tx: &RpcTransaction) -> ... {
    let signature_length = signature.0.len();
    if signature_length > self.config.max_signature_length { ... }
    Ok(())
}
``` [6](#0-5) 

### Impact Explanation

An adversary who observes (or creates) a situation where account `A` has a `nonce=2` Invoke in the mempool but no `nonce=1` Invoke can submit a `nonce=1` Invoke for account `A` with an **arbitrary/invalid signature**. The gateway admits it to the mempool without signature verification. This matches the impact category:

> **High. Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

Concrete consequences:
- **Griefing / nonce-slot squatting**: The adversary occupies account `A`'s `nonce=1` slot with an invalid transaction. The legitimate owner must use fee escalation to displace it, paying progressively higher fees.
- **Mempool pollution**: Invalid transactions consume pool capacity and batcher resources; they are only rejected (with fee charge to account `A`) during blockifier execution.
- **Fee drain**: If fee escalation is enabled, the adversary can repeatedly replace the `nonce=1` slot with higher-fee invalid transactions, draining account `A`'s balance without any authorized action by `A`.

### Likelihood Explanation

- **Unprivileged trigger**: Any external party can submit an RPC transaction; no special role or key is required.
- **Observable precondition**: A `nonce=2` (or higher) Invoke in the mempool for an account with on-chain `nonce=0` is a publicly observable state (mempool is gossiped over P2P).
- **No cryptographic barrier**: The adversary does not need the account's private key; any byte string of valid length passes stateless signature-size validation.
- **Narrow but real window**: The condition (`tx_nonce==1 && account_nonce==0 && pool contains address`) is specific but arises naturally whenever a user submits a future-nonce transaction before the preceding one.

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is present for the sender address, either in the pool or in a recent committed block. For example, expose a `deploy_account_in_pool_or_recent_block(address)` query from the mempool that filters by transaction type, and use that in `skip_stateful_validations`. This preserves the intended UX (deploy + invoke in one batch) while closing the bypass for arbitrary future-nonce Invokes.

### Proof of Concept

1. Account `A` exists on-chain with `nonce=0` and sufficient STRK balance.
2. Legitimate user (key `K1`) submits `Invoke(sender=A, nonce=2, calldata=..., signature=valid_sig_for_nonce2)` → passes all checks including `__validate__`; lands in mempool pool.
3. Adversary (key `K3`, no relation to `A`) submits `Invoke(sender=A, nonce=1, calldata=..., signature=GARBAGE)`:
   - **Stateless**: signature length ≤ `max_signature_length` → passes. [6](#0-5) 
   - **`validate_state_preconditions`**: `0 ≤ 1 ≤ max_allowed_nonce_gap` → passes. [7](#0-6) 
   - **`validate_by_mempool`**: no duplicate nonce=1, nonce valid → passes. [8](#0-7) 
   - **`skip_stateful_validations`**: `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` (step 2 tx is in pool) → returns `true`. [9](#0-8) 
   - **`run_validate_entry_point`**: `execution_flags.validate=false` → `__validate__` skipped, `Ok(())` returned. [10](#0-9) 
4. `K3`'s invalid `nonce=1` Invoke is now in the mempool. `K1`'s legitimate `nonce=1` Invoke is rejected as `DuplicateNonce` unless it pays a higher fee (fee escalation). The batcher eventually executes `K3`'s transaction, `__validate__` fails, the transaction is rejected, and the fee is charged to account `A`.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L287-296)
```rust
            _ => {
                let max_allowed_nonce =
                    Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
                if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
                    return Err(create_error(format!(
                        "Invalid transaction nonce. Expected: {account_nonce} <= nonce <= \
                         {max_allowed_nonce}, got: {incoming_tx_nonce}."
                    )));
                }
            }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L78-81)
```rust
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L49-57)
```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
```rust
    fn validate_tx_signature_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
    }
```
