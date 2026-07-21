### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions with Unverified Signatures When a Pending Deploy-Account Exists - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry point (the on-chain signature check) for any invoke transaction with `nonce == 1` when the sender's on-chain nonce is `0` and `account_tx_in_pool_or_recent_block` returns `true`. Because `account_tx_in_pool_or_recent_block` returns `true` whenever **any** transaction from that address is in the pool — not specifically a deploy-account — an unprivileged attacker who observes a victim's pending deploy-account can inject an invoke transaction carrying an arbitrary invalid signature into the mempool without any cryptographic verification.

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function returns `true` (skip validation) when three conditions hold simultaneously:

1. The incoming transaction is an `Invoke` with `tx.nonce() == Nonce(Felt::ONE)`.
2. The account's committed on-chain nonce is `Nonce(Felt::ZERO)` (account not yet deployed).
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

**Condition 3 is too broad.** The mempool check is: [2](#0-1) 

It returns `true` if **any** transaction from that address is in the pool or has ever been committed — it does not distinguish a deploy-account from an invoke. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but this reasoning is circular: the attacker's own invalid invoke is the transaction being admitted, and the victim's deploy-account is what satisfies the check.

**Effect — signature verification is skipped**

When `skip_validate == true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` call is bypassed entirely: [4](#0-3) 

No other gateway-level check verifies the cryptographic signature. The stateless validator only checks signature **length**, not validity: [5](#0-4) 

`validate_by_mempool` (called before `skip_stateful_validations`) checks nonce range and fee escalation only — it does not verify signatures: [6](#0-5) 

**Batcher re-validates, but the mempool invariant is already broken**

`AccountTransaction::new_for_sequencing` sets `validate: true`, so the batcher will call `__validate__` and the transaction will revert. However, the transaction has already been admitted to the mempool with an unverified signature, violating the admission invariant. [7](#0-6) 

### Impact Explanation

An attacker can inject invoke transactions with arbitrary invalid signatures into the mempool for any account that has a pending deploy-account. Concretely:

- **Mempool pollution / resource waste**: Invalid transactions consume mempool capacity and batcher execution resources.
- **Transaction replacement (griefing)**: If the victim has also submitted a legitimate invoke with `nonce=1`, the attacker can replace it by submitting with a higher fee (fee escalation). The victim's valid invoke is evicted; the attacker's invalid one takes its place, fails during execution, and the victim must resubmit.
- **Account activation DoS**: If the victim has not yet submitted their invoke, the attacker can pre-occupy `nonce=1` with an invalid transaction, forcing the victim to pay a higher fee to escalate past it.

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

- The victim's deploy-account transaction is observable via P2P gossip (public mempool).
- No cryptographic secret is required; the attacker only needs the victim's address.
- The attack is a single RPC call to `add_transaction` with a well-formed invoke body and a garbage signature.
- The triggering window is the time between the victim's deploy-account entering the mempool and being committed — which can be multiple blocks.

### Recommendation

1. **Narrow the mempool check**: `skip_stateful_validations` should verify that the transaction in the pool for the sender address is specifically a deploy-account transaction, not just any transaction. The mempool should expose a dedicated `has_pending_deploy_account(address)` query.
2. **Alternatively, do not skip signature verification**: The UX goal (accepting deploy-account + invoke in the same batch) can be achieved by deferring the invoke's `__validate__` call to after the deploy-account is executed in the same block, rather than skipping it at the gateway admission stage.
3. **Enforce a stricter precondition**: Before returning `true`, confirm that `tx_pool.contains_deploy_account(sender_address)` rather than `tx_pool.contains_account(sender_address)`.

### Proof of Concept

```
# Step 1: Victim submits a valid deploy-account for address A.
POST /add_transaction  { type: DEPLOY_ACCOUNT, sender: A, nonce: 0, sig: <valid> }
# → Accepted. Mempool now has deploy-account for A.
# → account_tx_in_pool_or_recent_block(A) == true

# Step 2: Attacker observes A in the mempool (P2P gossip).

# Step 3: Attacker submits an invoke with nonce=1 and a garbage signature.
POST /add_transaction  { type: INVOKE, sender: A, nonce: 1, sig: [0xdeadbeef, 0xcafebabe] }

# Gateway stateless check: signature length ≤ max_signature_length → PASS
# Gateway stateful:
#   account_nonce = get_nonce_from_state(A) = 0
#   validate_nonce: 0 ≤ 1 ≤ 200 → PASS
#   validate_by_mempool: nonce in range, no duplicate → PASS
#   skip_stateful_validations:
#     tx.nonce() == 1 ✓, account_nonce == 0 ✓,
#     account_tx_in_pool_or_recent_block(A) == true ✓  → returns true
#   run_validate_entry_point(skip_validate=true):
#     execution_flags.validate = false → __validate__ NOT called
# → Invalid invoke ADMITTED to mempool without signature verification.

# Step 4 (optional escalation): If victim also submitted invoke(A, nonce=1, valid_sig, fee=F),
# attacker re-submits with fee > F → victim's valid invoke is replaced by attacker's invalid one.
# Victim's transaction is evicted; attacker's fails during batcher execution.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
