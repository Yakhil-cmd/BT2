### Title
`skip_stateful_validations` allows any attacker to inject an unvalidated invoke transaction for a victim's undeployed account, bypassing `__validate__` and occupying the victim's nonce=1 slot — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator is designed to improve UX for users sending a `deploy_account` + `invoke` pair simultaneously. It skips the `__validate__` entry point for an invoke with `nonce=1` when the account's on-chain nonce is `0` and the account has any transaction in the mempool. The check uses `account_tx_in_pool_or_recent_block`, which returns `true` for **any** transaction from that address — not specifically a deploy_account submitted by the same user. Because the stateless validator only checks signature **length** (not validity), an attacker can craft an invoke for a victim's undeployed address with a garbage signature, satisfy all gateway checks, and have it admitted to the mempool without ever running `__validate__`. The victim's own valid invoke with `nonce=1` is then rejected as a duplicate nonce.

---

### Finding Description

**Root cause — `skip_stateful_validations` does not bind the skip to the account owner:** [1](#0-0) 

The function returns `true` (skip `__validate__`) when:
1. The transaction is `Invoke`
2. `tx.nonce() == 1`
3. `account_nonce == 0` (account not yet deployed on-chain)
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

Condition 4 is satisfied by **any** transaction from that address in the mempool — including the victim's own `deploy_account`. The function never checks that the invoke was submitted by the same party who submitted the `deploy_account`.

**`account_tx_in_pool_or_recent_block` checks any transaction, not deploy_account specifically:** [2](#0-1) [3](#0-2) 

**When `skip_validate=true`, `__validate__` is never called:** [4](#0-3) [5](#0-4) 

**Stateless validator only checks signature length, not validity:** [6](#0-5) 

**Nonce check in `validate_nonce` allows `nonce=1` when `account_nonce=0`:** [7](#0-6) 

**Mempool's `validate_tx` only rejects duplicate hash or nonce-too-old:** [8](#0-7) [9](#0-8) 

**Full gateway flow — `validate_by_mempool` then `skip_stateful_validations` then `run_validate_entry_point`:** [10](#0-9) [11](#0-10) 

---

### Impact Explanation

**Matching impact**: *High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

An attacker can:
1. Observe a victim's `deploy_account` (nonce=0) enter the mempool.
2. Immediately submit `Invoke { sender_address: victim_addr, nonce: 1, signature: [garbage, garbage] }` with valid resource bounds.
3. The gateway accepts it: stateless check passes (length OK), nonce check passes (1 ≥ 0), mempool `validate_tx` passes (no duplicate), `skip_stateful_validations` returns `true` (victim's deploy_account is in pool), `__validate__` is skipped entirely.
4. The attacker's invalid invoke occupies `(victim_addr, nonce=1)` in the mempool.
5. The victim's own valid invoke with `nonce=1` is rejected with `DuplicateNonce` (or requires fee escalation).
6. When the block is built, the attacker's invoke reaches the blockifier with `validate=true`; `__validate__` fails (garbage signature); the transaction is included as a failed transaction and the victim's nonce is consumed.

The victim's first post-deployment invoke is permanently blocked or consumed by the attacker's invalid transaction.

---

### Likelihood Explanation

The attack requires only:
- Observing the victim's `deploy_account` in the mempool (visible via P2P gossip or RPC)
- Submitting a crafted invoke before the victim submits their own invoke with `nonce=1`

No privileged access, no special knowledge of the victim's private key, and no on-chain funds are required. The victim's account address is deterministic and computable from the `deploy_account` transaction fields. The window is the time between the victim's `deploy_account` entering the mempool and the victim submitting their own `nonce=1` invoke.

---

### Recommendation

The `skip_stateful_validations` function must verify that the transaction in the mempool for the sender address is specifically a `deploy_account`, not just any transaction. The simplest fix is to query the mempool for a deploy_account specifically, or to restrict the skip to cases where the mempool contains a `deploy_account` at `nonce=0` for the sender address.

A minimal diff analogous to the external report's fix:

```diff
- // We verify that a deploy_account transaction exists for this account. It is sufficient
- // to check if the account exists in the mempool since it means that either it has a
- // deploy_account transaction or transactions with future nonces that passed validations.
- return mempool_client
-     .account_tx_in_pool_or_recent_block(tx.sender_address())
-     .await
+ // We verify that a deploy_account transaction exists for this account.
+ // Only skip validation if the mempool contains a deploy_account for this address.
+ return mempool_client
+     .deploy_account_in_pool(tx.sender_address())
+     .await
```

This requires adding a `deploy_account_in_pool` query to the mempool that checks specifically for a `DeployAccount` transaction at `nonce=0` for the address, rather than any transaction.

---

### Proof of Concept

```
1. Victim computes their future account address A (deterministic from class_hash, salt, constructor_calldata).
2. Victim submits: DeployAccount { contract_address: A, nonce: 0, signature: [valid_sig] }
   → Gateway accepts, mempool now has A in tx_pool.

3. Attacker observes A in the mempool.
4. Attacker submits: Invoke { sender_address: A, nonce: 1, signature: [0x1234, 0x5678] }
   (garbage signature, valid length, valid resource bounds)

5. Gateway stateless check: signature length OK → pass
6. Gateway convert: tx_hash computed
7. Gateway stateful:
   - validate_nonce: nonce=1, account_nonce=0, 0 ≤ 1 ≤ max_allowed_nonce_gap → pass
   - validate_by_mempool: no duplicate hash, tx_nonce=1 ≥ account_nonce=0 → pass
   - skip_stateful_validations:
       tx is Invoke ✓, tx.nonce()==1 ✓, account_nonce==0 ✓
       account_tx_in_pool_or_recent_block(A) == true (victim's deploy_account) ✓
       → returns true (skip __validate__)
   - run_validate_entry_point(skip_validate=true): ExecutionFlags{validate:false} → __validate__ NOT called
8. Attacker's invoke added to mempool at (A, nonce=1).

9. Victim submits: Invoke { sender_address: A, nonce: 1, signature: [valid_sig] }
   → mempool validate_tx: DuplicateNonce { address: A, nonce: 1 } → REJECTED

10. Block built: deploy_account(A) executes (success, nonce→1).
    Attacker's invoke executes: __validate__ called with garbage sig → FAIL.
    Victim's nonce=1 is consumed by the failed transaction.
    Victim must now use nonce=2 for their first real invoke.
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L162-174)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        let TransactionReference { address, nonce: tx_nonce, .. } = tx_reference;
        let account_nonce = self.resolve_nonce(address, incoming_account_nonce);
        if tx_nonce < account_nonce {
            return Err(MempoolError::NonceTooOld { address, tx_nonce, account_nonce });
        }

        Ok(())
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-194)
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
```
