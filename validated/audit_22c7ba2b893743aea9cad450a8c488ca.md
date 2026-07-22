### Title
Gateway Skips `__validate__` Signature Check for Invoke Transactions When Deploy-Account Is Pending in Mempool — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally bypasses the `__validate__` entry-point call (the account's signature-verification step) for any invoke transaction with `nonce == 1` when the account's on-chain nonce is `0` and **any** transaction from that sender address exists in the mempool. An attacker who observes a victim's pending `deploy_account` transaction can submit a forged invoke transaction with an invalid or empty signature targeting the same address, and the gateway will admit it to the mempool without ever calling `__validate__`. This is the direct Sequencer analog of the TradeCallee bug: just as TradeCallee uses `tx.origin` to authorize fund transfers without verifying the order was signed by `tx.origin`, the gateway uses the presence of a deploy-account in the mempool as a proxy for authorization without verifying the invoke transaction's signature.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip validation) when three conditions hold simultaneously:
1. The transaction is an `Invoke` with `nonce == 1`
2. The account's on-chain nonce is `0` (account not yet deployed)
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`

Condition 3 is satisfied by **any** transaction from that sender address in the mempool — it is not restricted to `DeployAccount` transactions: [2](#0-1) 

**Effect on the validate entry point:**

When `skip_validate == true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

The blockifier's `StatefulValidator::perform_validations` then returns `Ok(())` immediately without calling `__validate__`: [4](#0-3) 

**The mempool's `validate_tx` does not check signatures either:**

`ValidationArgs` carries only `address`, `account_nonce`, `tx_hash`, `tx_nonce`, `tip`, and `max_l2_gas_price` — no signature field: [5](#0-4) 

The mempool's `validate_tx` only checks nonce validity and fee escalation: [6](#0-5) 

**Result:** An invoke transaction with an arbitrary or empty signature is admitted to the mempool with zero cryptographic verification.

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions.**

An attacker can inject unsigned or maliciously-signed invoke transactions into the mempool for any account that has a pending `deploy_account` transaction. Concretely:

1. The attacker's forged invoke (nonce=1, invalid signature, arbitrary calldata) occupies the nonce-1 slot in the mempool for the victim's address.
2. The victim's legitimate invoke (also nonce=1) is rejected with `DuplicateNonce` unless it pays a higher fee than the attacker's transaction (fee-escalation rule).
3. The mempool is polluted with transactions that will fail `__validate__` during batcher execution and be rejected — wasting sequencer resources and degrading throughput.
4. The attacker can repeat this for every new `deploy_account` observed in the mempool, creating a systematic griefing vector against all new account deployments.

The batcher does re-run `__validate__` with `validate=true` via `new_for_sequencing`, so the forged transaction will not be executed on-chain. However, the admission invariant — *every transaction in the mempool must have passed signature verification* — is broken at the gateway layer. [7](#0-6) 

---

### Likelihood Explanation

**Likelihood: High.** The attack requires only:
- Monitoring the public mempool for `deploy_account` transactions (trivially observable via the gateway's RPC).
- Submitting a well-formed invoke transaction with the victim's address as `sender_address`, `nonce=1`, and any (invalid) signature.

No privileged access, no special contract deployment, and no prior relationship with the victim is required. The attack window is the time between the victim's `deploy_account` entering the mempool and being committed to a block.

---

### Recommendation

**Short term:** In `skip_stateful_validations`, replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`DeployAccount`** transaction for the sender address exists in the mempool. Additionally, even when skipping the blockifier `__validate__` call, perform a lightweight off-chain ECDSA signature check against the transaction hash and the account's expected public key (derivable from the deploy_account's constructor calldata) before admitting the invoke to the mempool.

**Long term:** Ensure that the `skip_validate` UX shortcut never results in a transaction being admitted to the mempool without any form of authorization proof. The invariant "every transaction in the mempool has a verified signature" must hold unconditionally. Consider making the skip conditional on the gateway having already verified the signature independently of the blockifier path.

---

### Proof of Concept

1. Alice submits `deploy_account` for address `A` (class hash `C`, salt `S`, constructor arg = public key `pk_alice`). This transaction enters the mempool; `account_tx_in_pool_or_recent_block(A)` now returns `true`.

2. Eve observes Alice's pending `deploy_account` and constructs:
   ```
   InvokeV3 {
     sender_address: A,
     nonce: 1,
     calldata: [<arbitrary malicious calls>],
     signature: [],   // empty — no valid ECDSA signature
     resource_bounds: <valid>,
     ...
   }
   ```

3. Eve submits this to the gateway. The gateway executes:
   - `StatelessTransactionValidator::validate` — passes (empty signature is within `max_signature_length` if configured ≥ 0, and no signature content check is done stateless).
   - `extract_state_nonce_and_run_validations`:
     - `get_nonce_from_state(A)` → `0` (account not deployed yet).
     - `run_pre_validation_checks`: nonce `1` is within `[0, 0 + max_gap]` — passes.
     - `skip_stateful_validations`: `nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true` → returns `true`.
     - `run_validate_entry_point(skip_validate=true)`: sets `validate=false`, calls `StatefulValidator::validate` which returns `Ok(())` immediately without calling `__validate__`.
   - Transaction is forwarded to the mempool and admitted.

4. Eve's forged invoke now occupies nonce-1 for address `A` in the mempool. Alice's legitimate invoke (also nonce=1) is rejected with `MempoolError::DuplicateNonce` unless Alice pays a higher fee. [8](#0-7) [9](#0-8)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L50-70)
```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}

impl ValidationArgs {
    pub fn new(tx: &AccountTransaction, account_nonce: Nonce) -> Self {
        Self {
            address: tx.sender_address(),
            account_nonce,
            tx_hash: tx.tx_hash(),
            tx_nonce: tx.nonce(),
            tip: tx.tip(),
            max_l2_gas_price: tx.resource_bounds().get_l2_bounds().max_price_per_unit,
        }
    }
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
