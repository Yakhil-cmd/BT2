### Title
Gateway Skips `__validate__` Signature Check for Invoke Transactions with Nonce=1 When Account Has Pending Deploy-Account — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway unconditionally skips the account's `__validate__` entry point (the only on-chain signature check) for any invoke transaction whose nonce is `1` and whose sender account has any transaction in the mempool or a recent block. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can front-run the victim's paired invoke by submitting a forged invoke with an arbitrary/invalid signature. The gateway accepts the forged invoke without verifying the signature, inserts it into the mempool, and the victim's legitimate invoke is subsequently rejected as a duplicate nonce. The forged invoke later reverts on-chain (consuming the victim's nonce), permanently invalidating the victim's intended action.

---

### Finding Description

**Root cause — `skip_stateful_validations`**

In `crates/apollo_gateway/src/stateful_transaction_validator.rs` lines 429–461, the function `skip_stateful_validations` returns `true` (skip validation) when all three conditions hold:

1. The incoming transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` **and** `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` constructs `ExecutionFlags` with `validate: false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false` the function returns `Ok(())` immediately after `perform_pre_validation_stage`, never calling `validate_tx` (the `__validate__` entry point): [3](#0-2) 

The transaction is then forwarded to the mempool via `mempool_client.add_tx(add_tx_args)` with no signature ever verified. [4](#0-3) 

**`validate_by_mempool` does not check signatures**

The mempool's `validate_tx` only checks for duplicate tx-hash and nonce/fee-escalation rules — it never inspects the cryptographic signature: [5](#0-4) 

**`account_tx_in_pool_or_recent_block` is not deploy-account-specific**

The check returns `true` for any transaction from the account, not only `DeployAccount`: [6](#0-5) 

**Batcher uses `validate: true`**

When the batcher later executes the forged invoke it uses `new_for_sequencing`, which sets `validate: true` and `strict_nonce_check: true`. The `__validate__` entry point is called, the invalid signature causes a revert, and the account nonce is still incremented to `2`. The victim's legitimate invoke (nonce `1`) is now permanently stale. [7](#0-6) 

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts an invalid transaction before sequencing.**

An attacker can insert a signature-less (or arbitrarily-signed) invoke transaction for any victim account that has a pending `deploy_account` in the mempool. The concrete consequences are:

* The victim's legitimate invoke (nonce `1`) is either rejected as `DuplicateNonce` or displaced via fee escalation.
* The forged invoke is executed on-chain, reverts, and increments the victim's nonce to `2`.
* The victim's intended action is permanently lost; they must resubmit with nonce `2` and pay additional fees.
* With fee escalation enabled, the attacker can guarantee displacement by offering a marginally higher tip.

---

### Likelihood Explanation

The attack requires only:

1. Observing the mempool for `deploy_account` transactions (public information on any full node).
2. Submitting an invoke with nonce `1`, the victim's sender address, and any (invalid) signature before the victim's own invoke reaches the gateway.

No privileged access, special keys, or on-chain state is required. The race window is the latency between the victim's `deploy_account` being accepted and their paired invoke being submitted — a window that is deliberately widened by the UX feature itself.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a `DeployAccount` transaction for the sender is pending. Alternatively, require that the invoke transaction carry a valid signature even when validation is skipped at the gateway level (i.e., still call `__validate__` but tolerate a `SKIP_VALIDATE` magic return value as Starknet's protocol allows), or record the expected deploy-account tx-hash alongside the invoke and verify the pairing before skipping validation.

---

### Proof of Concept

1. Victim submits `deploy_account` (nonce `0`, address `A`) to the gateway. It passes all checks and enters the mempool.
2. Attacker queries the mempool, observes `deploy_account` for address `A`.
3. Attacker constructs `invoke` with `sender_address = A`, `nonce = 1`, `calldata = [arbitrary]`, `signature = [0x0]` (invalid).
4. Attacker submits the forged invoke to the gateway.
5. Gateway path:
   - `StatelessTransactionValidator::validate` — passes (signature length ≤ max, resource bounds non-zero, DA modes L1).
   - `convert_rpc_tx_to_internal_and_executable_txs` — succeeds (no class lookup needed for invoke).
   - `validate_state_preconditions` — passes (`0 ≤ 1 ≤ max_allowed_nonce_gap`).
   - `validate_by_mempool` — passes (no existing nonce-1 tx for `A`).
   - `skip_stateful_validations` — returns `true` (`nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true`).
   - `run_validate_entry_point` — `validate: false` → returns `Ok(())` without calling `__validate__`.
6. Forged invoke is added to the mempool.
7. Victim submits legitimate invoke (nonce `1`, valid signature). Gateway calls `validate_by_mempool` → `DuplicateNonce` error. Victim's invoke is rejected.
8. Batcher executes: `deploy_account` (nonce `0`) succeeds; forged invoke (nonce `1`) calls `__validate__`, fails on invalid signature, reverts; account nonce is now `2`.
9. Victim's legitimate invoke (nonce `1`) is permanently invalid.

### Citations

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

                Ok(())
            }
```

**File:** crates/apollo_gateway/src/gateway.rs (L286-286)
```rust
        let mempool_client_result = self.mempool_client.add_tx(add_tx_args).await;
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```
