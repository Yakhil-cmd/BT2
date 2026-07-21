### Title
Gateway Admits Unsigned Invoke Transactions for Undeployed Accounts via `skip_stateful_validations` — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call (i.e., signature verification) for any invoke transaction with nonce=1 targeting an account whose on-chain nonce is 0, provided that *any* transaction for that address already exists in the mempool. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit a forged invoke with nonce=1 for the victim's address, carrying arbitrary calldata and a random signature, and have it admitted to the mempool without any signature check.

### Finding Description

`skip_stateful_validations` is called from `run_pre_validation_checks` after the mempool's lightweight `validate_tx` (which only checks nonce ordering and duplicate hashes, not signatures):

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:429-461
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
                ...
        }
    }
    Ok(false)
}
```

When this returns `true`, `run_validate_entry_point` sets `validate: false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

This means `blockifier_validator.validate(account_tx)` is called with `execution_flags.validate = false`, so `validate_tx` inside the blockifier returns `Ok(None)` immediately without executing the account's `__validate__` entry point and without checking the signature.

The guard condition relies on `account_tx_in_pool_or_recent_block`, which returns `true` if the mempool's `tx_pool` or `state` contains *any* transaction for the address — it does not verify that the existing transaction is a `deploy_account` submitted by the legitimate owner:

```rust
// crates/apollo_mempool/src/mempool.rs:697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

The mempool's `validate_tx` (called before `skip_stateful_validations`) only checks:
1. Duplicate transaction hash
2. Nonce ordering (`tx_nonce >= account_nonce`)
3. Fee escalation / duplicate nonce for the same address

None of these checks verify the signature.

**Attack path:**

1. Victim submits `deploy_account` for address A (nonce=0). It passes full validation and enters the mempool.
2. Attacker observes address A in the mempool via `account_tx_in_pool_or_recent_block`.
3. Attacker submits `Invoke(sender=A, nonce=1, calldata=<arbitrary>, signature=<garbage>)`.
4. Gateway stateless checks pass (valid address, resource bounds, size).
5. `validate_nonce` passes: `0 <= 1 <= 0 + max_allowed_nonce_gap`.
6. `validate_by_mempool` passes: nonce=1 ≥ account_nonce=0, no duplicate hash.
7. `skip_stateful_validations` returns `true` because `account_tx_in_pool_or_recent_block(A) == true`.
8. `run_validate_entry_point` is called with `validate=false` — **no signature check**.
9. The forged invoke is admitted to the mempool.

If the attacker's forged invoke reaches the mempool before the victim's legitimate invoke with nonce=1, the victim's invoke is rejected with `MempoolError::DuplicateNonce`, breaking the victim's deploy_account + invoke flow entirely.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions and rejects valid transactions before sequencing.**

- An invalid invoke transaction (wrong signature, arbitrary calldata) is admitted to the mempool without signature verification.
- The victim's legitimate invoke with nonce=1 is subsequently rejected by the mempool (`DuplicateNonce`), because the attacker's forged transaction already occupies that nonce slot.
- The victim's deploy_account + invoke UX flow is broken: the deploy_account executes, the attacker's forged invoke fails during blockifier execution (signature check in `__validate__` fails, transaction reverts), and the victim's invoke never executes.
- No state change occurs from the forged invoke (it reverts), but the nonce slot is consumed and the victim's transaction is blocked.

### Likelihood Explanation

- The attack requires no privileged access. Any observer of the public mempool can execute it.
- The deploy_account + invoke UX pattern is explicitly supported and documented in the codebase, making it a predictable target.
- The attacker only needs to front-run the victim's invoke submission, which is straightforward when monitoring the mempool.
- The window of vulnerability is the time between the victim's `deploy_account` entering the mempool and the victim's invoke with nonce=1 being submitted.

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction for the target address exists in the mempool, not just any transaction. Alternatively, require that the invoke transaction's sender address matches the sender of the pending `deploy_account` transaction in the mempool, or cryptographically bind the invoke to the deploy_account (e.g., by requiring the invoke to reference the deploy_account's transaction hash).

A minimal fix: expose a `deploy_account_in_pool(address)` query on the mempool that returns `true` only if a `DeployAccount` transaction (not just any transaction) is pending for that address.

### Proof of Concept

```
1. Victim generates keypair (sk_v, pk_v), computes deploy address A from class_hash + salt + [pk_v].
2. Victim submits RpcTransaction::DeployAccount { sender=A, nonce=0, signature=valid_sig_v }.
   → Passes full validation, enters mempool.
3. Attacker queries mempool: account_tx_in_pool_or_recent_block(A) == true.
4. Attacker submits RpcTransaction::Invoke {
       sender=A, nonce=1,
       calldata=[<drain_funds_calldata>],
       signature=[0x1, 0x2]  // garbage
   }.
   → StatelessTransactionValidator: passes (valid address, non-zero resource bounds, size ok).
   → validate_nonce: 0 <= 1 <= max_allowed_nonce_gap → passes.
   → validate_by_mempool: nonce=1 >= 0, no duplicate hash → passes.
   → skip_stateful_validations: nonce==1 && account_nonce==0 && account_in_pool==true → returns true.
   → run_validate_entry_point: validate=false → __validate__ NOT called → admitted.
5. Attacker's invoke is now in the mempool at (A, nonce=1).
6. Victim submits their legitimate invoke { sender=A, nonce=1, signature=valid_sig_v }.
   → validate_by_mempool → validate_fee_escalation → DuplicateNonce { address=A, nonce=1 } → REJECTED.
7. Block is built: deploy_account(A) executes (nonce 0→1), attacker's invoke executes,
   __validate__ fails (bad signature) → reverts. Victim's invoke never executes.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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
