### Title
Signature Verification Bypassed for Invoke Transactions via `skip_stateful_validations` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function unconditionally skips the `__validate__` entry point (which is where account contracts verify signatures) for any invoke transaction with `nonce=1` when the on-chain account nonce is `0` and `account_tx_in_pool_or_recent_block` returns `true`. Because this check does not verify that the submitter is the account owner, any third party can submit an invoke transaction for a victim account that has a pending `deploy_account` in the mempool, using an arbitrary/invalid signature, and have it admitted to the mempool without any signature verification.

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which calls `skip_stateful_validations`:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...;
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

With `validate = false`, the blockifier's `validate_tx` immediately returns `Ok(None)` without calling `__validate__`:

```rust
fn validate_tx(...) -> TransactionExecutionResult<Option<CallInfo>> {
    if !self.execution_flags.validate {
        return Ok(None);
    }
    ...
}
``` [3](#0-2) 

In Starknet, ECDSA signature verification is performed exclusively inside the account contract's `__validate__` entry point (as shown in the reference account contract):

```rust
fn validate_transaction(self: @ContractState) -> felt252 {
    let tx_info = starknet::get_tx_info().unbox();
    let signature = tx_info.signature;
    assert(check_ecdsa_signature(...), 'INVALID_SIGNATURE');
    starknet::VALIDATED
}
``` [4](#0-3) 

The stateless validator only checks signature **length**, not cryptographic validity:

```rust
fn validate_tx_signature_size(&self, tx: &RpcTransaction) -> ... {
    let signature_length = signature.0.len();
    if signature_length > self.config.max_signature_length {
        return Err(StatelessTransactionValidatorError::SignatureTooLong { ... });
    }
    Ok(())
}
``` [5](#0-4) 

The mempool's `validate_tx` only checks nonce/fee escalation — it receives no signature field at all:

```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
``` [6](#0-5) 

The `account_tx_in_pool_or_recent_block` check only verifies that the account has **any** transaction in the mempool or recent block — it does not verify that the submitter is the account owner, nor that the existing transaction is specifically a `deploy_account`:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [7](#0-6) 

### Impact Explanation

An attacker who observes that account `A` has a pending `deploy_account` transaction in the mempool can:

1. Craft an invoke transaction with `sender_address=A`, `nonce=1`, arbitrary calldata, and a syntactically valid but cryptographically invalid signature (e.g., `[0x1, 0x2]`).
2. Submit it to the gateway.
3. The gateway passes stateless validation (signature length is within bounds).
4. The gateway stateful path sees `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` → `skip_validate=true`.
5. `__validate__` is never called; the invalid signature is never checked.
6. The transaction is admitted to the mempool.

The attacker's transaction now occupies nonce=1 for account `A`. When the legitimate user submits their own invoke with nonce=1, the mempool rejects it as `DuplicateNonce`. If fee escalation is disabled, the legitimate transaction is permanently blocked until the attacker's transaction is eventually rejected during block execution. If fee escalation is enabled, the attacker can keep outbidding to maintain the squatting.

This matches the **High** impact: *Mempool/gateway/RPC admission accepts invalid transactions before sequencing.*

### Likelihood Explanation

- Triggering the condition requires only that the victim account has a pending `deploy_account` in the mempool, which is publicly observable via RPC.
- No privileged access is required; any unprivileged party can submit transactions to the gateway.
- The attacker needs no knowledge of the victim's private key.
- The attack is cheap: only a single well-formed (but cryptographically invalid) invoke transaction is needed per victim account.

### Recommendation

The `skip_stateful_validations` function should not be the sole guard for bypassing signature verification. Two options:

1. **Restrict the skip to the account owner**: Require that the transaction be submitted alongside a proof of ownership (e.g., a valid `deploy_account_tx_hash` that matches the pending deploy_account in the mempool, as the `PyValidator` path does in `native_blockifier`).

   The `PyValidator::should_run_stateful_validations` already requires `deploy_account_tx_hash.is_some()` as a caller-supplied hint: [8](#0-7) 

   The new gateway path (`skip_stateful_validations`) does not require this hint and relies solely on the mempool state, making it exploitable by any third party.

2. **Verify the deploy_account transaction hash**: When skipping `__validate__`, additionally verify that the `deploy_account` transaction in the mempool was submitted with a transaction hash that matches the expected address derivation for the invoke's `sender_address`, ensuring the skip is only applied to the legitimate account owner's invoke.

### Proof of Concept

```
// Precondition: account A has a deploy_account tx in the mempool (nonce=0, account_nonce=0)

// Attacker submits:
RpcInvokeTransactionV3 {
    sender_address: A,          // victim's address
    nonce: 1,                   // post-deploy nonce
    calldata: [<arbitrary>],    // any calldata
    signature: [0x1, 0x2],      // invalid ECDSA signature, but length <= max_signature_length
    resource_bounds: <valid>,
    ...
}

// Gateway flow:
// 1. stateless: signature length 2 <= max_signature_length → OK
// 2. stateful: account_nonce=0, tx.nonce()=1, account_tx_in_pool_or_recent_block(A)=true
//    → skip_validate = true
// 3. run_validate_entry_point: execution_flags.validate = false → __validate__ NOT called
// 4. Transaction admitted to mempool with nonce=1 for account A

// Consequence:
// Legitimate user submits invoke(sender=A, nonce=1, valid_signature)
// → MempoolError::DuplicateNonce { address: A, nonce: 1 }
// → Legitimate transaction blocked
``` [9](#0-8)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-461)
```rust
    async fn run_pre_validation_checks(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<bool> {
        self.validate_state_preconditions(executable_tx, account_nonce).await?;
        validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
    }
}

/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
}

/// Check if validation of an invoke transaction should be skipped due to deploy_account not being
/// processed yet. This feature is used to improve UX for users sending deploy_account + invoke at
/// once.
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/blockifier_test_utils/resources/feature_contracts/cairo1/account_with_real_validate.cairo (L28-43)
```text
        fn validate_transaction(self: @ContractState) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            let signature = tx_info.signature;
            assert(signature.len() == 2_u32, 'INVALID_SIGNATURE_LENGTH');
            assert(
                check_ecdsa_signature(
                    message_hash: tx_info.transaction_hash,
                    public_key: self.public_key.read(),
                    signature_r: *signature[0_u32],
                    signature_s: *signature[1_u32],
                ),
                'INVALID_SIGNATURE',
            );

            starknet::VALIDATED
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/native_blockifier/src/py_validator.rs (L109-118)
```rust
        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```
