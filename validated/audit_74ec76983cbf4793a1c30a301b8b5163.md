### Title
`skip_stateful_validations` Bypasses Signature Verification for Invoke Transactions via Overly Broad `account_tx_in_pool_or_recent_block` Check — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function is designed to improve UX by allowing the first invoke (nonce=1) from a newly-deploying account to skip blockifier signature validation when a `deploy_account` is pending. However, the predicate it uses — `account_tx_in_pool_or_recent_block` — is too broad: it returns `true` for **any** transaction from the sender address in the pool, not specifically a `deploy_account`. An unprivileged attacker who observes a `deploy_account` for address X in the public mempool can submit an invoke from X with nonce=1 and an **invalid signature**, have it admitted to the mempool without any signature check, and potentially displace the legitimate user's invoke via fee escalation.

### Finding Description

**Step 1 — The skip condition is triggered by any pool membership, not deploy_account specifically.** [1](#0-0) 

The function returns `true` (skip validation) when:
- tx is `Invoke`
- `tx.nonce() == 1`
- `account_nonce == 0` (account not yet deployed in state)
- `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

The comment acknowledges the check is broader than deploy_account:
> "it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**"

The underlying mempool implementation confirms this: [2](#0-1) 

`self.state.contains_account(account_address) || self.tx_pool.contains_account(account_address)` — this is true for **any** address that has ever had a transaction in the pool or a recent committed block, regardless of transaction type.

**Step 2 — When `skip_validate = true`, `execution_flags.validate` is set to `false`.** [3](#0-2) 

**Step 3 — The blockifier's `StatefulValidator::perform_validations` returns `Ok(())` immediately when `validate = false`, without calling `__validate__`.** [4](#0-3) 

The `__validate__` entry point — which is where account contracts check ECDSA signatures — is never invoked. The `validate_tx` implementation confirms this: [5](#0-4) 

**Step 4 — `perform_pre_validation_stage` still runs (nonce, fee bounds, balance), but NOT signature.** [6](#0-5) 

The balance check (`verify_can_pay_committed_bounds`) can be satisfied by an attacker pre-funding address X with STRK tokens before submitting the invalid invoke, since Starknet allows token transfers to non-existent addresses.

**Attack scenario:**

1. Legitimate user submits `deploy_account` for address X → admitted to pool after passing `__validate_deploy__`.
2. Attacker observes X in the public mempool.
3. Attacker sends STRK tokens to X (pre-funds the non-existent account).
4. Attacker submits `Invoke` from X, `nonce=1`, **invalid signature**, sufficient resource bounds.
5. Gateway: `account_nonce=0` ✓, `tx.nonce()=1` ✓, `account_tx_in_pool_or_recent_block(X)=true` ✓ → `skip_validate=true`.
6. `perform_pre_validation_stage` passes (nonce ≥ 0, fee bounds met, balance covered by pre-funding).
7. `validate=false` → `__validate__` is never called → invalid invoke admitted to mempool.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An unprivileged attacker can inject cryptographically invalid invoke transactions into the mempool for any address that has a pending `deploy_account`. At execution time the batcher calls `__validate__` with `validate=true` and the transaction reverts, but the damage is already done at admission:

- **Mempool pollution / DoS**: The attacker can flood the mempool with invalid transactions for every observable `deploy_account`, consuming mempool capacity.
- **Displacement attack**: If the mempool supports fee escalation (replacing a same-nonce transaction with a higher-fee one), the attacker's invalid invoke can evict the legitimate user's nonce=1 invoke, causing it to be lost.
- **Wasted sequencer execution**: Invalid transactions are included in blocks as reverted transactions, consuming block space and execution resources.

### Likelihood Explanation

**Medium.** The attacker requires no privileged access. The mempool is observable (public). Pre-funding a non-existent address with STRK is a standard token transfer. The only cost is the STRK needed to pass the balance check and the gas for the pre-fund transfer. The window is open for as long as the `deploy_account` remains unprocessed.

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists in the pool for the sender address. The mempool should expose a dedicated `has_pending_deploy_account(address)` query that inspects transaction types, rather than returning `true` for any pool membership. Alternatively, restrict the skip path to only trigger when the mempool confirms a `deploy_account` with matching `contract_address` is pending.

### Proof of Concept

```
// Precondition: legitimate user has submitted deploy_account for address X.
// X is visible in the mempool. account_nonce(X) == 0 in state.

// Step 1: Attacker pre-funds X with STRK to pass verify_can_pay_committed_bounds.
strk_token.transfer(X, sufficient_amount);

// Step 2: Attacker crafts invoke with nonce=1, invalid signature.
let attacker_invoke = RpcInvokeTransactionV3 {
    sender_address: X,
    nonce: 1,
    signature: TransactionSignature(vec![Felt::from(0xdeadbeef)].into()), // invalid
    resource_bounds: AllResourceBounds { l2_gas: sufficient_bounds, .. },
    calldata: ...,
    ..
};

// Step 3: Submit to gateway.
// Gateway path:
//   skip_stateful_validations returns true because:
//     tx.nonce() == 1  ✓
//     account_nonce == 0  ✓
//     account_tx_in_pool_or_recent_block(X) == true  ✓ (deploy_account is in pool)
//
//   run_validate_entry_point sets execution_flags.validate = false
//   StatefulValidator::perform_validations returns Ok(()) without calling __validate__
//   Invalid invoke is admitted to mempool.
gateway.add_tx(attacker_invoke).await; // succeeds
```

The relevant code path confirming the early return without signature check: [7](#0-6)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-96)
```rust
    pub fn perform_validations(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        // Deploy account transaction should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        // Declare transaction should also be fully executed - otherwise, if we only go through
        // the validate phase, we would miss the check that the class was not declared before.
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
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
        }
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
