### Title
Signature Bypass via `skip_stateful_validations` Allows Arbitrary Invoke Transactions for Undeployed Accounts — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator unconditionally skips the `__validate__` entry point — and therefore all cryptographic signature verification — for any invoke transaction with `nonce == 1` whenever *any* transaction from the sender address is present in the mempool. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit an invoke transaction with a garbage signature for the victim's not-yet-deployed address, and the gateway will accept it without ever checking the signature.

---

### Finding Description

`skip_stateful_validations` returns `true` (skip validation) when three conditions hold simultaneously:

```
tx is Invoke  AND  tx.nonce() == 1  AND  account_nonce == 0
AND  account_tx_in_pool_or_recent_block(sender_address) == true
``` [1](#0-0) 

When `skip_validate == true`, `run_validate_entry_point` sets `validate: !skip_validate = false`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, the `__validate__` call is guarded by `tx.execution_flags.validate`: [3](#0-2) 

So when the flag is `false`, the function returns `Ok(())` immediately after `perform_pre_validation_stage`, and the account's `__validate__` entry point — which is the only place the ECDSA signature is checked — is never invoked.

The third condition (`account_tx_in_pool_or_recent_block`) only verifies that *some* transaction from the sender address exists in the mempool or a recent block: [4](#0-3) 

It does **not** verify that the incoming invoke transaction's signature is valid, nor that the submitter of the invoke is the same entity who submitted the `deploy_account`. The stateless validator only checks signature *length*, not cryptographic correctness: [5](#0-4) 

The analog to the external `ecrecover` report is exact: just as `delegateBySig` recovered a signer address from the signature without binding the owner's address in the digest, the gateway here derives admission from the presence of *any* mempool entry for the address — without binding the signature to the account's actual public key.

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker submits an invoke transaction with a garbage signature for a victim's not-yet-deployed account. The gateway accepts it into the mempool without signature verification. When the batcher executes the block:

1. The victim's `deploy_account` (nonce 0) executes and deploys the account.
2. The attacker's invoke (nonce 1) executes; `__validate__` is now called and fails (garbage signature); the transaction reverts but **the nonce is consumed** (incremented to 2).
3. The victim's legitimate invoke with nonce 1 is either rejected by the mempool as a duplicate nonce or fails at execution time with `InvalidNonce`.

The victim's first post-deployment invoke is permanently blocked. The attacker pays nothing (the reverted transaction charges fees from the victim's account, which may be zero at that point, resulting in no charge).

---

### Likelihood Explanation

**Likelihood: Medium.**

- The mempool is public; any observer can detect a `deploy_account` transaction for address X.
- Submitting a garbage invoke with `sender_address = X`, `nonce = 1`, and an arbitrary signature is a single RPC call.
- No privileged access, no cryptographic work, and no special knowledge of the victim's private key is required.
- The only constraint is timing: the attacker must submit before the `deploy_account` is included in a block (i.e., while `account_nonce` is still 0).

---

### Recommendation

1. **Do not skip `__validate__` entirely.** Instead, run `__validate__` against a simulated post-deployment state (the account class is known from the `deploy_account` transaction in the mempool). This is the correct fix: verify the signature even when the account is not yet on-chain.

2. **Alternatively, tighten the skip condition** to require that the mempool entry for the address is specifically a `deploy_account` transaction (not just any transaction), and cross-check that the invoke's `sender_address` matches the `contract_address` computed from that specific `deploy_account`.

3. **At minimum**, add a note that the current skip path accepts transactions with unverified signatures, and ensure the batcher's execution-time revert does not permanently consume the victim's nonce slot in a way that blocks legitimate follow-on transactions.

---

### Proof of Concept

```
1. Victim Alice submits:
     deploy_account { class_hash: C, salt: S, constructor_calldata: [pk_alice] }
     → contract_address X is deterministically computed
     → accepted into mempool (account_nonce for X = 0)

2. Attacker observes X in mempool, submits:
     invoke {
       sender_address: X,
       nonce: 1,
       calldata: [anything],
       signature: [0x0, 0x0]   ← garbage
     }

3. Gateway stateful validator:
     account_nonce(X) = 0  ✓
     tx.nonce() = 1         ✓
     account_tx_in_pool_or_recent_block(X) = true  ✓  (Alice's deploy_account)
     → skip_validate = true
     → __validate__ NOT called
     → transaction accepted into mempool

4. Batcher executes block:
     nonce 0: Alice's deploy_account executes → X deployed with public key pk_alice
     nonce 1: Attacker's invoke executes → __validate__ called → ECDSA fails → REVERT
              nonce for X incremented to 2

5. Alice's legitimate invoke with nonce=1 is now blocked:
     - If mempool rejects duplicate nonces: Alice's invoke was already rejected at step 3.
     - If not: Alice's invoke fails at execution with InvalidNonce (nonce 1 already consumed).
```

**Root cause** (exact lines): [6](#0-5) 

The `account_tx_in_pool_or_recent_block` check is a necessary but not sufficient guard: it confirms the account is *expected* to exist, but it does not authenticate the invoke transaction's submitter, leaving the signature entirely unverified for this admission path.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-458)
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
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
    }
```
