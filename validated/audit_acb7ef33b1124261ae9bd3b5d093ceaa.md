### Title
Gateway Signature Validation Bypass via `skip_stateful_validations` Allows Cryptographically Invalid Invoke Transactions into Mempool — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator unconditionally skips the `__validate__` entry point (which performs signature verification) for any invoke transaction with `nonce == 1` targeting an account whose on-chain nonce is `0` and which has any transaction present in the mempool. An unprivileged attacker can exploit this by first submitting a valid `deploy_account` transaction for a chosen address, then immediately submitting an invoke transaction with `nonce=1` for that same address carrying an arbitrary/invalid signature. The gateway admits the invalid invoke transaction to the mempool without ever verifying the signature.

---

### Finding Description

The gateway's stateful validation path calls `run_pre_validation_checks`, which in turn calls `skip_stateful_validations`: [1](#0-0) 

`skip_stateful_validations` returns `true` when three conditions hold simultaneously: [2](#0-1) 

1. The transaction is an `Invoke` variant.
2. `tx.nonce() == Nonce(Felt::ONE)` — hardcoded to exactly nonce 1.
3. `account_nonce == Nonce(Felt::ZERO)` — account not yet deployed on-chain.
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

When `skip_validate` is `true`, `run_validate_entry_point` constructs the `AccountTransaction` with `validate: false`: [3](#0-2) 

Inside the blockifier's `validate_tx`, this flag causes an immediate early return without executing the `__validate__` entry point: [4](#0-3) 

The `account_tx_in_pool_or_recent_block` check is satisfied by the presence of **any** transaction for the account in the mempool pool or state — not specifically a `deploy_account` transaction: [5](#0-4) 

The mempool's own `validate_tx` (called via `validate_by_mempool` before the skip check) only validates nonce ordering, fee escalation, and duplicate hashes — it does **not** verify signatures: [6](#0-5) 

The `StatefulTransactionValidatorConfig` contains a `max_nonce_for_validation_skip` field, but the gateway's `skip_stateful_validations` function **never reads it** — the nonce=1 check is hardcoded, creating a discrepancy between the config and the implementation: [7](#0-6) 

---

### Impact Explanation

An attacker can inject a cryptographically invalid invoke transaction (arbitrary/zero signature) into the mempool for any account address they choose. The mempool enforces a `DuplicateNonce` error for a second transaction at the same nonce: [8](#0-7) 

This means:

- **Scenario A (self-created condition):** Attacker submits a valid `deploy_account` for address Y, then immediately submits an invalid invoke (nonce=1, garbage signature) for Y. Both are admitted. The invalid invoke occupies nonce=1 in the mempool. Any subsequent legitimate invoke at nonce=1 from the real owner of Y is rejected with `DuplicateNonce`.

- **Scenario B (targeting a victim):** Attacker observes a victim's pending `deploy_account` in the mempool, races to submit an invalid invoke (nonce=1) for the victim's address before the victim submits their own invoke. The victim's legitimate invoke is then rejected.

In both cases the invalid transaction is eventually rejected at execution time by the batcher (which uses `validate: true` via `AccountTransaction::new_for_sequencing`), but the mempool slot at nonce=1 is occupied until the block is committed and the rejected hash is reported back. This constitutes **mempool admission of an invalid transaction** and enables targeted disruption of the deploy-account + invoke UX flow.

---

### Likelihood Explanation

The mempool is publicly observable. Any attacker can monitor for `deploy_account` transactions and race to submit an invalid invoke for the same address. The attack requires no privileged access, no special knowledge of the victim's private key, and no on-chain funds beyond the gas required for the attacker's own `deploy_account` transaction. The race window is the time between the victim's `deploy_account` being admitted to the mempool and the victim submitting their first invoke.

---

### Recommendation

1. **Verify the mempool entry is specifically a `deploy_account` transaction**, not just any transaction, before skipping validation. The comment in the code acknowledges this is the intent but the implementation does not enforce it.

2. **Use the `max_nonce_for_validation_skip` config field** that already exists in `StatefulTransactionValidatorConfig` instead of the hardcoded `Nonce(Felt::ONE)` check, and ensure the gateway reads it: [7](#0-6) 

3. **Consider requiring a minimum structural signature check** (e.g., non-empty, non-zero) even when skipping full `__validate__` execution, to raise the cost of the attack.

---

### Proof of Concept

```
1. Attacker picks a salt S and class_hash C, computes deterministic address Y.

2. Attacker submits a valid deploy_account tx:
     sender = Y, nonce = 0, class_hash = C, salt = S, valid signature

3. Gateway admits it; mempool now has Y in pool.
   account_tx_in_pool_or_recent_block(Y) == true.

4. Attacker immediately submits an invalid invoke tx:
     sender = Y, nonce = 1, calldata = [arbitrary], signature = [0x0, 0x0]

5. Gateway stateful validation path:
   - validate_state_preconditions: nonce=1 >= account_nonce=0, passes.
   - validate_by_mempool: no duplicate hash/nonce, passes.
   - skip_stateful_validations:
       tx.nonce() == Nonce(ONE)  ✓
       account_nonce == Nonce(ZERO)  ✓
       account_tx_in_pool_or_recent_block(Y) == true  ✓
     → returns true (skip_validate = true)
   - run_validate_entry_point called with validate=false → __validate__ NOT called.

6. Invalid invoke tx admitted to mempool with nonce=1 for address Y.

7. Victim (real owner of Y) submits their legitimate invoke tx (nonce=1):
   → Mempool rejects with DuplicateNonce { address: Y, nonce: 1 }.

8. Attacker's invalid tx is eventually executed by batcher, fails __validate__,
   is marked rejected. Victim must wait for next block and resubmit.
``` [2](#0-1) [9](#0-8) [10](#0-9)

### Citations

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

**File:** crates/apollo_gateway_config/src/config.rs (L283-283)
```rust
    pub max_nonce_for_validation_skip: Nonce,
```

**File:** crates/apollo_mempool/src/fee_mempool_test.rs (L543-543)
```rust
#[case::equal_nonce(1, MempoolError::DuplicateNonce { address: contract_address!("0x0"), nonce: nonce!(1) })]
```
