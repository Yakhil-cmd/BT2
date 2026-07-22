### Title
Signature Validation Bypass via `skip_stateful_validations` Admits Unsigned Invoke Transactions to Mempool - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator completely bypasses the `__validate__` entry-point call (which performs signature verification) for any invoke transaction with nonce=1 when the sender address has *any* transaction in the mempool or recent block. An attacker who first submits a valid `deploy_account` for an address they control can then submit an invoke with nonce=1 carrying a forged or empty signature, and the gateway will admit it to the mempool without any signature check. The same technique can be used to replace a victim's legitimate pending invoke (via fee escalation) with an unsigned one.

---

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which in turn calls `skip_stateful_validations`: [1](#0-0) 

`skip_stateful_validations` returns `true` (skip) when all three conditions hold: [2](#0-1) 

The three conditions are:
1. The transaction is an `Invoke`
2. `tx.nonce() == 1` and `account_nonce == 0`
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

Condition 3 is satisfied by **any** transaction from that address being in the pool or committed state — it is not restricted to `deploy_account` transactions: [3](#0-2) 

When `skip_validate = true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, completely suppressing the `__validate__` entry-point call: [4](#0-3) 

The two pre-validation steps that run before `skip_stateful_validations` — `validate_state_preconditions` and `validate_by_mempool` — check only nonce range and fee escalation; neither inspects the signature: [5](#0-4) [6](#0-5) 

During actual block execution the batcher constructs transactions with `AccountTransaction::new_for_sequencing`, which sets `validate: true`: [7](#0-6) 

So the forged invoke will revert at execution time, but it has already been admitted to the mempool.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An invoke transaction carrying a forged or empty signature is admitted to the mempool without any cryptographic check. Concrete consequences:

1. **Mempool spam / DoS**: An attacker who pre-funds and deploys one address can continuously submit unsigned invokes with nonce=1 for that address, flooding the mempool with transactions that will all revert on execution.

2. **Griefing via fee escalation**: If a victim has already submitted a legitimate `deploy_account + invoke(nonce=1)` pair, an attacker who observes the pending `deploy_account` can submit an invoke with nonce=1 for the victim's address with a higher tip and `max_l2_gas_price`. The mempool's fee-escalation logic (`validate_fee_escalation` → `remove_replaced_tx`) will silently replace the victim's valid invoke with the attacker's unsigned one: [8](#0-7) 

The victim's legitimate invoke is permanently evicted; the attacker's unsigned invoke later reverts during execution, leaving the victim's nonce=1 slot empty.

---

### Likelihood Explanation

**Medium.** The attacker must:
- Submit one valid `deploy_account` (requires pre-funding the address with enough STRK/ETH to pass fee checks during gateway validation).
- Submit an invoke with nonce=1 carrying any signature (including an empty one).

Both steps are straightforward for any unprivileged user. The griefing variant additionally requires monitoring the public mempool for pending `deploy_account` transactions, which is trivially observable.

---

### Recommendation

The skip-validate shortcut should verify that the transaction in the mempool for the sender address is specifically a `deploy_account`, not just any transaction. Additionally, even when skipping the on-chain `__validate__` call, the gateway should perform an off-chain signature pre-check (e.g., verify the ECDSA signature against the account's expected public key derived from the pending `deploy_account`'s constructor calldata) before admitting the invoke. At minimum, `account_tx_in_pool_or_recent_block` should be replaced with a stricter `deploy_account_in_pool(sender_address)` query that only returns `true` when a `deploy_account` specifically is pending.

---

### Proof of Concept

```
// Step 1 – Attacker generates a key pair and computes the deterministic address `addr`.
// Step 2 – Attacker pre-funds `addr` with STRK.
// Step 3 – Attacker submits a valid deploy_account for `addr` (signed with their key).
//           Gateway runs full StatefulValidator::execute() on it → passes → admitted to mempool.
//           Now: account_tx_in_pool_or_recent_block(addr) == true.

// Step 4 – Attacker submits an invoke:
//   sender_address = addr
//   nonce          = 1
//   calldata       = <arbitrary>
//   signature      = []   // empty / forged

// Gateway path:
//   validate_state_preconditions: nonce 1 >= account_nonce 0 ✓, resource bounds ✓
//   validate_by_mempool:          no duplicate nonce, fee escalation ok ✓
//   skip_stateful_validations:
//     tx is Invoke ✓, nonce==1 ✓, account_nonce==0 ✓,
//     account_tx_in_pool_or_recent_block(addr) == true ✓
//     → returns true (skip)
//   run_validate_entry_point(skip_validate=true):
//     ExecutionFlags { validate: false, ... }
//     → __validate__ is NEVER called → no signature check
//   → invoke admitted to mempool with forged signature

// Step 5 (griefing variant):
//   Victim submits deploy_account + invoke(nonce=1, valid_sig, tip=T).
//   Attacker submits invoke(nonce=1, forged_sig, tip=T*1.11) for victim's address.
//   Fee escalation replaces victim's invoke with attacker's unsigned one.
//   Victim's invoke is lost; attacker's invoke reverts at execution time.
``` [2](#0-1) [9](#0-8) [3](#0-2)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-314)
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
