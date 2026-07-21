### Title
Signature Verification Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Admission — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator skips the `__validate__` entry point (the account's signature check) for invoke transactions with nonce=1 when the on-chain account nonce is 0 and `account_tx_in_pool_or_recent_block` returns `true`. Because that mempool query returns `true` for **any** transaction from the sender's address — not exclusively a `deploy_account` — an unprivileged attacker who observes a victim's `deploy_account` in the mempool can immediately submit an invoke with an arbitrary/invalid signature on behalf of the victim's not-yet-deployed address, have it admitted by the gateway without signature verification, and thereby block the victim's legitimate nonce-1 invoke from entering the mempool.

---

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function fires when an incoming invoke has `tx.nonce() == 1` and the on-chain `account_nonce == 0`. It then calls:

```rust
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address()).await
```

and returns `true` (skip validation) if that call returns `true`.

**What `account_tx_in_pool_or_recent_block` actually checks** [2](#0-1) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

It returns `true` if **any** transaction from that address is in the pool — including the victim's own `deploy_account` that the attacker just observed.

**What happens when `skip_validate = true`** [3](#0-2) 

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

`validate = false` → `validate_tx` returns `Ok(None)` immediately without calling `__validate__`: [4](#0-3) 

```rust
if !self.execution_flags.validate {
    return Ok(None);
}
```

**Gateway `add_tx` flow — no other signature guard exists before mempool insertion** [5](#0-4) 

The stateless validator checks only format/size/DA-mode — no signature content: [6](#0-5) 

The nonce range check (`validate_nonce`) passes for nonce=1 with account_nonce=0 and `max_allowed_nonce_gap=200`: [7](#0-6) 

**Attack steps**

1. Victim broadcasts `deploy_account` (nonce=0) for address `A`. It enters the mempool.
2. Attacker observes the `deploy_account` in the mempool; computes address `A` from its `class_hash`, `salt`, `constructor_calldata`.
3. Attacker submits `Invoke V3` with `sender_address=A`, `nonce=1`, `signature=[0x0, 0x0]` (arbitrary).
4. Gateway stateless check passes (format/size OK).
5. `get_nonce_from_state(A)` → `0` (account not yet deployed).
6. `validate_nonce`: `0 ≤ 1 ≤ 200` → passes.
7. `validate_by_mempool`: no duplicate nonce=1 for address `A` yet → passes.
8. `skip_stateful_validations`: nonce=1, account_nonce=0, `account_tx_in_pool_or_recent_block(A)` = `true` (victim's `deploy_account` is in the pool) → returns `true`.
9. `run_validate_entry_point(skip_validate=true)` → `validate=false` → `__validate__` **not called** → gateway accepts the transaction.
10. Attacker's invalid invoke is inserted into the mempool with nonce=1 for address `A`.
11. Victim submits their legitimate invoke (nonce=1, valid signature) → mempool rejects it: `DuplicateNonce { address: A, nonce: 1 }`. [8](#0-7) 

12. Batcher picks up the attacker's fake invoke; blockifier calls `__validate__` → fails (invalid signature) → transaction rejected, nonce **not** incremented, fee **not** charged.
13. Victim must resubmit their invoke in the next block.

---

### Impact Explanation

**Invariant broken:** The gateway admits an invoke transaction whose signature has never been verified. This directly matches the allowed impact: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

Concrete consequences:
- An attacker can inject a signature-less invoke for any address that has a pending `deploy_account`, at zero cost (rejected transactions are not charged fees).
- The victim's legitimate nonce-1 invoke is blocked from the mempool for one full block cycle.
- The attack is repeatable: after the fake invoke is evicted, the attacker can immediately re-submit another one for the next nonce.

---

### Likelihood Explanation

- `deploy_account` transactions are publicly visible in the mempool.
- The target address is deterministically computable from the `deploy_account` fields.
- No special privilege, stake, or prior relationship with the victim is required.
- The attacker pays nothing: the fake invoke is rejected (not reverted) by the blockifier, so no fee is charged.
- The production config sets `max_nonce_for_validation_skip = 0x1`, confirming the feature is live: [9](#0-8) 

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a query that specifically confirms a `deploy_account` transaction is present for the sender's address. For example, expose a `deploy_account_in_pool(address)` method on the mempool that inspects transaction type, and use that in `skip_stateful_validations` instead of the generic presence check. [10](#0-9) 

---

### Proof of Concept

```
// 1. Victim submits deploy_account for address A (class_hash=X, salt=Y, calldata=Z).
//    A = pedersen(X, Y, Z, deployer=0)  [deterministic]

// 2. Attacker observes deploy_account in mempool, computes A.

// 3. Attacker crafts:
RpcInvokeTransactionV3 {
    sender_address: A,
    nonce: 1,
    signature: [Felt::ZERO, Felt::ZERO],   // invalid
    resource_bounds: <valid bounds>,
    calldata: [],
    ...
}

// 4. POST /gateway/add_transaction  →  HTTP 200, tx_hash returned.
//    (skip_stateful_validations returns true because victim's deploy_account
//     is in the pool for address A)

// 5. Victim's legitimate invoke (nonce=1, valid sig) →  HTTP 400 DuplicateNonce.

// 6. Next block: batcher executes fake invoke → __validate__ fails → rejected.
//    Victim resubmits invoke → accepted.
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/apollo_mempool/src/mempool.rs (L757-791)
```rust
    /// `(address, nonce)` via fee escalation, without mutating any state. Returns the existing
    /// transaction to be replaced when a valid replacement exists, `None` when there is nothing to
    /// replace, or an error when a replacement is present but not permitted.
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
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_gateway/src/gateway.rs (L214-298)
```rust
    async fn add_tx_inner(
        &self,
        tx: RpcTransaction,
        p2p_message_metadata: Option<BroadcastedMessageMetadata>,
    ) -> GatewayResult<GatewayOutput> {
        let mut metric_counters = GatewayMetricHandle::new(&tx, &p2p_message_metadata);
        metric_counters.count_transaction_received();
        if let RpcTransaction::Invoke(RpcInvokeTransaction::V3(ref inv)) = tx {
            if !inv.proof_facts.is_empty() {
                metric_counters.count_private_transaction_received();
            }
        }
        let is_p2p = p2p_message_metadata.is_some();

        if let RpcTransaction::Declare(ref declare_tx) = tx {
            if let Err(e) = self.check_declare_permissions(declare_tx) {
                metric_counters.record_add_tx_failure(&e);
                return Err(e);
            }
        }

        // Perform stateless validations.
        self.stateless_tx_validator.validate(&tx)?;

        let tx_signature = tx.signature().clone();

        // Declare conversions overload the compiler component's CPU and memory. Reject declares if
        // there are too many declares compiling in parallel. The permit is held only across
        // compilation and released before stateful validation.
        let compilation_permit = if matches!(tx, RpcTransaction::Declare(_)) {
            Some(self.declare_compilation_semaphore.try_acquire().map_err(|_| {
                let error = StarknetError::too_many_concurrent_declare_compilations();
                metric_counters.record_add_tx_failure(&error);
                error
            })?)
        } else {
            None
        };

        let (internal_tx, executable_tx, proof_data) =
            self.convert_rpc_tx_to_internal_and_executable_txs(tx, &tx_signature).await?;
        drop(compilation_permit);

        let mut stateful_transaction_validator = self
            .stateful_tx_validator_factory
            .instantiate_validator(self.config.dynamic_config.native_classes_whitelist.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let nonce = stateful_transaction_validator
            .extract_state_nonce_and_run_validations(&executable_tx, self.mempool_client.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let proof_archive_handle = self
            .store_proof_and_spawn_archiving(proof_data, internal_tx.tx_hash, is_p2p)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let gateway_output = create_gateway_output(&internal_tx);

        let add_tx_args = AddTransactionArgsWrapper {
            args: AddTransactionArgs::new(internal_tx, nonce),
            p2p_message_metadata,
        };

        // Await as late as possible for proof archiving before sending the transaction to the
        // mempool.
        Self::await_proof_archiving(proof_archive_handle)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let mempool_client_result = self.mempool_client.add_tx(add_tx_args).await;
        match mempool_client_result_to_deprecated_gw_result(&tx_signature, mempool_client_result) {
            Ok(()) => {}
            Err(e) => {
                metric_counters.record_add_tx_failure(&e);
                return Err(e);
            }
        };

        metric_counters.transaction_sent_to_mempool();

        Ok(gateway_output)
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-54)
```rust
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
    }
```

**File:** crates/apollo_deployments/resources/app_configs/replacer_gateway_config.json (L18-18)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": "0x1",
```
