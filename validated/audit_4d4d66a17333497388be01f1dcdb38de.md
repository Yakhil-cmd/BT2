### Title
Gateway Admits Invoke Transactions with Invalid Signatures via `skip_stateful_validations` Bypass — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator bypasses `__validate__` (signature verification) for invoke transactions with `nonce == 1` when a deploy_account transaction for the same sender address is already in the mempool. Because the deploy_account address is fully deterministic and public, any observer can submit an invoke transaction from a victim's pre-computed, not-yet-deployed account address with an arbitrary invalid signature, and the gateway will admit it to the mempool without any signature check.

---

### Finding Description

The gateway's `extract_state_nonce_and_run_validations` flow is:

1. Read on-chain nonce for the sender address.
2. Run `run_pre_validation_checks` (nonce range, resource bounds, mempool duplicate check).
3. Call `skip_stateful_validations` to decide whether to skip `__validate__`.
4. Call `run_validate_entry_point` with `validate: !skip_validate`. [1](#0-0) 

`skip_stateful_validations` returns `true` (skip signature verification) when all three conditions hold:

```
tx.nonce() == Nonce(Felt::ONE)
  && account_nonce == Nonce(Felt::ZERO)
  && account_tx_in_pool_or_recent_block(tx.sender_address()) == true
``` [2](#0-1) 

When `skip_validate == true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

With `validate: false`, `validate_tx` returns `Ok(None)` immediately — `__validate__` is never called: [4](#0-3) 

`account_tx_in_pool_or_recent_block` returns `true` if the address has **any** transaction in the pool — including a deploy_account submitted by the legitimate owner: [5](#0-4) 

The deploy_account address is fully deterministic from public fields (`class_hash`, `contract_address_salt`, `constructor_calldata`, deployer = 0): [6](#0-5) 

**Attack chain:**

1. Victim submits `deploy_account(class_hash=C, salt=S, calldata=D)`. The transaction enters the mempool pool, so `tx_pool.contains_account(victim_addr)` becomes `true`.
2. Attacker computes `victim_addr` deterministically from `(C, S, D)` (all public from the mempool transaction).
3. Attacker submits `invoke(sender=victim_addr, nonce=1, signature=<garbage>)`.
4. Gateway reads on-chain nonce for `victim_addr` → `0` (account not deployed).
5. `validate_nonce` passes: nonce=1 is within the allowed gap for invoke.
6. `validate_by_mempool` passes: no duplicate tx_hash, nonce ≥ account_nonce.
7. `skip_stateful_validations`: nonce==1, account_nonce==0, `account_tx_in_pool_or_recent_block` == `true` → returns `true`.
8. `run_validate_entry_point` runs with `validate: false` → `__validate__` is **never called**.
9. Gateway returns success; attacker's invoke is added to the mempool.

The mempool's `validate_fee_escalation` will reject a second transaction at the same `(address, nonce)` unless fee escalation applies: [7](#0-6) 

So the attacker's invalid invoke occupies the `nonce=1` slot for the victim's address. The victim's legitimate invoke (also `nonce=1`) is then rejected with `DuplicateNonce` unless it offers a higher fee — but even with fee escalation, the attacker can keep replacing with higher-fee invalid transactions at negligible cost (rejected transactions pay no fees because `__validate__` fails at execution time).

When the batcher eventually executes the attacker's invoke, it uses `new_for_sequencing` which sets `validate: true`: [8](#0-7) 

`__validate__` then fails (invalid signature), the transaction is rejected, and the batcher notifies the mempool. But the attacker can immediately re-submit another invalid invoke, repeating the cycle indefinitely.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway's admission invariant — that every accepted invoke transaction has passed signature verification — is broken for the specific case of `nonce=1` invokes targeting an address with a pending deploy_account. An unprivileged attacker can:

- Continuously inject signature-invalid invoke transactions into the mempool for any address that has a pending deploy_account.
- Occupy the `nonce=1` slot, blocking or delaying the victim's legitimate first post-deploy invoke.
- Spam the mempool at zero net cost (no fees charged for transactions rejected at `__validate__`).

---

### Likelihood Explanation

Deploy_account transactions are publicly visible in the mempool. The target address is deterministic and trivially computable. No special privileges, funds, or prior state are required. The attack requires only the ability to submit transactions to the gateway, which is open to all. Any user deploying a new account is exposed for the window between deploy_account submission and block inclusion.

---

### Recommendation

The `skip_stateful_validations` check must verify that the account in the pool has a **deploy_account** transaction specifically, not just any transaction. The current check `account_tx_in_pool_or_recent_block` is too broad — it returns `true` for any transaction type from that address.

A targeted fix: query the mempool for whether the pending transaction for `(address, nonce=0)` is specifically a `DeployAccount` type before granting the skip. Alternatively, require that the invoke's signature be verified even in the skip-validate path by running a lightweight signature check without full `__validate__` execution, or by storing the transaction type alongside the address in the mempool's account tracking.

---

### Proof of Concept

```
// Precondition: victim_addr is deterministic from (class_hash, salt, calldata)
// Step 1: victim submits deploy_account → enters mempool pool
//   account_tx_in_pool_or_recent_block(victim_addr) == true

// Step 2: attacker submits:
RpcInvokeTransactionV3 {
    sender_address: victim_addr,   // pre-computed
    nonce: 1,
    signature: [0xdeadbeef],       // arbitrary garbage
    calldata: [],
    resource_bounds: <valid>,
    ...
}

// Step 3: gateway stateful validation
//   account_nonce = get_nonce(victim_addr) = 0   (not deployed)
//   validate_nonce: 0 <= 1 <= 0+max_gap  → OK
//   validate_by_mempool: no dup hash, nonce >= 0 → OK
//   skip_stateful_validations:
//     nonce==1 && account_nonce==0 && pool_contains(victim_addr)==true → true
//   run_validate_entry_point(skip_validate=true):
//     execution_flags.validate = false
//     validate_tx → Ok(None)  // __validate__ never called
//   → gateway returns Ok, tx added to mempool

// Step 4: victim's legitimate invoke(nonce=1) arrives
//   validate_fee_escalation: (victim_addr, nonce=1) already in pool
//   → MempoolError::DuplicateNonce  (unless fee escalation threshold met)
//   → victim's invoke is rejected or must pay escalated fee

// Step 5: batcher executes attacker's invoke
//   new_for_sequencing → validate: true
//   __validate__ runs → signature invalid → transaction rejected
//   attacker pays no fee; can immediately re-submit
``` [9](#0-8) [2](#0-1) [10](#0-9) [11](#0-10)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-356)
```rust
    #[sequencer_latency_histogram(GATEWAY_VALIDATE_TX_LATENCY, true)]
    async fn run_validate_entry_point(
        &mut self,
        executable_tx: &ExecutableTransaction,
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );

        // Move state into the blocking task and run CPU-heavy validation.
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
            })
        })
        .await
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::UnknownErrorCode(
                "StarknetErrorCode.InternalError".to_string(),
            ),
            message: format!("Blocking task join error when running the validate entry point: {e}"),
        })?
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::ValidateFailure),
            message: e.to_string(),
        })?;
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-410)
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L760-792)
```rust
    fn validate_fee_escalation(
        &self,
        incoming_tx_reference: TransactionReference,
    ) -> MempoolResult<Option<TransactionReference>> {
        let TransactionReference { address, nonce, .. } = incoming_tx_reference;

        self.validate_no_delayed_declare_front_run(incoming_tx_reference)?;

        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
        }

        let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
        else {
            // Replacement irrelevant: no existing transaction with the same nonce for address.
            return Ok(None);
        };

        if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
            info!(
                "{existing_tx_reference} was not replaced by {incoming_tx_reference} due to \
                 insufficient fee escalation."
            );
            // TODO(Elin): consider adding a more specific error type / message.
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }

        Ok(Some(existing_tx_reference))
    }
```

**File:** crates/starknet_api/src/transaction.rs (L459-473)
```rust
impl<T: DeployTransactionTrait> CalculateContractAddress for T {
    /// Calculates the contract address for the contract deployed by a deploy account transaction.
    /// For more details see:
    /// <https://docs.starknet.io/learn/cheatsheets/transactions-reference#deploy-account-v3>
    fn calculate_contract_address(&self) -> StarknetApiResult<ContractAddress> {
        // When the contract is deployed via a deploy-account transaction, the deployer address is
        // zero.
        const DEPLOYER_ADDRESS: ContractAddress = ContractAddress(PatriciaKey::ZERO);
        calculate_contract_address(
            self.contract_address_salt(),
            self.class_hash(),
            self.constructor_calldata(),
            DEPLOYER_ADDRESS,
        )
    }
```
