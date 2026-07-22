### Title
Attacker Bypasses `__validate__` Signature Check on Invoke Transactions via `skip_stateful_validations` Race Against Victim's Pending `deploy_account` — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function skips the blockifier `__validate__` entry-point call for any invoke with `tx_nonce == 1` when `account_nonce == 0` and `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. The pool check is satisfied by **any** transaction from that address — including a victim's `deploy_account` — not exclusively a `deploy_account` owned by the same signer. An unprivileged attacker who observes a victim's `deploy_account` in the mempool can submit an invoke bearing the victim's `sender_address`, `nonce = 1`, and an **arbitrary/invalid signature**; the gateway accepts it without ever calling `__validate__`, admitting an unauthenticated transaction into the mempool.

### Finding Description

**Relevant code path** (`extract_state_nonce_and_run_validations` → `run_pre_validation_checks` → `skip_stateful_validations`): [1](#0-0) 

The condition that triggers the skip:

```
tx.nonce() == Nonce(Felt::ONE)   // tx_nonce == 1
&& account_nonce == Nonce(Felt::ZERO)  // account not yet deployed
&& account_tx_in_pool_or_recent_block(sender_address) == true
```

`account_tx_in_pool_or_recent_block` is: [2](#0-1) 

It returns `true` if **any** transaction from that address is in `tx_pool` or `state` (staged/committed). It does not check whether the pooled transaction is a `deploy_account`, nor whether it was submitted by the same signer.

When `skip_validate == true`, `run_validate_entry_point` sets `ExecutionFlags { validate: false }`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, an invoke with `validate: false` returns `Ok(())` immediately without calling `__validate__`: [4](#0-3) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks for duplicate tx-hash and nonce ordering: [5](#0-4) 

`MempoolState::validate_incoming_tx` resolves the account nonce from staged/committed maps; for a brand-new address those maps are empty, so it falls back to `incoming_account_nonce = 0`, and `tx_nonce 1 >= 0` passes: [6](#0-5) 

No existing nonce-1 entry exists for the victim's address (only nonce-0 `deploy_account`), so `validate_fee_escalation` also passes. The attacker's invoke clears every gateway check and is forwarded to the mempool via `add_tx`.

### Impact Explanation

**High — Mempool/gateway admission accepts an invalid (unauthenticated) transaction before sequencing.**

1. The gateway admits an invoke whose signature was never verified, violating the invariant that every accepted invoke has passed `__validate__`.
2. Because the attacker's nonce-1 entry now occupies the victim's nonce slot, the victim's legitimate invoke (nonce = 1) is rejected by the mempool with `DuplicateNonce` unless the victim pays a higher fee to trigger fee-escalation replacement. This is a targeted, low-cost denial-of-service against the deploy-account + invoke UX flow.

### Likelihood Explanation

**Medium.** The attacker only needs to:
1. Observe a `deploy_account` for target address `A` in the public mempool (visible via P2P gossip or RPC snapshot).
2. Craft an invoke with `sender_address = A`, `nonce = 1`, valid resource bounds, and any signature bytes.
3. Submit it to the gateway before the victim submits their own nonce-1 invoke.

No privileged access, no private key material, and no special network position are required.

### Recommendation

1. **Narrow the pool check**: `skip_stateful_validations` should query the mempool for a `deploy_account` specifically at `sender_address`, not just any transaction. Expose a dedicated `deploy_account_in_pool(address) -> bool` API on the mempool, or filter by transaction type inside `account_tx_in_pool_or_recent_block`.
2. **Verify signer identity**: Before skipping `__validate__`, confirm that the pooled transaction is a `deploy_account` whose computed `contract_address` equals the invoke's `sender_address`.

### Proof of Concept

```
1. Victim submits deploy_account(class_hash=C, salt=S, nonce=0) → address A.
   Gateway validates fully (constructor + __validate_deploy__), adds to mempool.
   mempool.tx_pool.contains_account(A) == true.

2. Attacker observes A in mempool snapshot / P2P.

3. Attacker submits:
     Invoke { sender_address: A, nonce: 1, calldata: [arbitrary], signature: [0x0] }

4. Gateway stateless check: passes (valid resource bounds, nonce DA mode L1, etc.)

5. Gateway stateful check:
   a. account_nonce = state.get_nonce(A) = 0  (A not yet deployed)
   b. validate_nonce: 0 <= 1 <= max_allowed_nonce_gap  → OK
   c. validate_by_mempool(nonce=1, account_nonce=0):
        resolve_nonce(A, 0) = 0  (staged/committed empty for A)
        1 >= 0  → OK
        no existing nonce-1 tx for A  → fee_escalation OK
   d. skip_stateful_validations:
        tx_nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
        → returns true
   e. run_validate_entry_point(skip_validate=true):
        ExecutionFlags { validate: false }
        StatefulValidator returns Ok(()) without calling __validate__

6. Gateway calls mempool.add_tx(attacker_invoke).
   Attacker's unauthenticated invoke is now in the mempool at (A, nonce=1).

7. Victim submits their legitimate invoke(sender=A, nonce=1, valid_sig).
   mempool.validate_tx → DuplicateNonce { address: A, nonce: 1 }  → REJECTED.

Victim's invoke is denied unless they pay a higher fee to replace the attacker's entry.
``` [7](#0-6) [1](#0-0) [2](#0-1) [8](#0-7)

### Citations

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
