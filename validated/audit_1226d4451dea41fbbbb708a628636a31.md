### Title
Gateway Signature Verification Bypass via `skip_stateful_validations` Allows Admission of Invoke Transactions with Invalid Signatures - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry point (the account's signature-verification step) for any invoke transaction with nonce=1 sent to an undeployed account, whenever `account_tx_in_pool_or_recent_block` returns `true`. Because that check returns `true` for **any** transaction type in the pool for that address — not exclusively a deploy-account — an unprivileged attacker who observes a victim's deploy-account in the mempool can inject an invoke with an arbitrary/invalid signature for the victim's address, bypassing signature verification at the gateway admission layer.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip validation) when:
- The incoming transaction is an `Invoke`
- `tx.nonce() == Nonce(Felt::ONE)` (nonce 1)
- `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed in state)
- `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

The comment claims this is safe because the pool entry "means that either it has a deploy_account transaction or transactions with future nonces that passed validations." However, `account_tx_in_pool_or_recent_block` checks for **any** transaction type: [2](#0-1) 

It returns `true` if the address appears in `self.state` (committed/staged) **or** `self.tx_pool` (any pooled transaction). A victim's deploy-account in the pool satisfies this condition.

**Effect — `run_validate_entry_point` with `validate: false`:** [3](#0-2) 

When `skip_validate=true`, `execution_flags.validate` is set to `false`. The blockifier's `StatefulValidator::perform_validations` then short-circuits before calling `__validate__`: [4](#0-3) 

And `AccountTransaction::validate_tx` also returns `Ok(None)` immediately: [5](#0-4) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce ordering and duplicate hashes — it performs no signature verification: [6](#0-5) 

---

### Impact Explanation

An attacker can inject an invoke transaction carrying an **arbitrary/invalid signature** for a victim's undeployed account address into the mempool, bypassing the account's `__validate__` entry point at the gateway admission layer. This breaks the core invariant of Starknet account abstraction: that only transactions whose signatures are accepted by the account contract may enter the sequencer pipeline.

Concrete consequences:
- The attacker's invalid invoke occupies the `(victim_address, nonce=1)` slot in the mempool.
- With fee escalation enabled (`enable_fee_escalation = true`), the attacker can replace the victim's legitimate nonce-1 invoke by offering a higher fee, permanently displacing it.
- The victim's legitimate invoke is evicted and must be resubmitted; the attacker's invalid invoke will fail `__validate__` during batcher execution and be rejected without fee charge.
- This is a repeatable, low-cost griefing vector against any account that submits a deploy-account + invoke pair.

Impact category: **High — Mempool/gateway admission accepts an invalid transaction (invalid signature) before sequencing.**

---

### Likelihood Explanation

The attack requires only:
1. Observing a pending deploy-account transaction in the mempool (publicly visible via RPC).
2. Submitting a single invoke with nonce=1 for the victim's address with any signature.

No privileged access, no special contract, no cryptographic capability is required. The condition `account_nonce == 0 && tx_nonce == 1 && account_in_pool` is trivially satisfiable for any new account deployment. The attack is fully unprivileged and reachable from the public RPC endpoint.

---

### Recommendation

**Short term:** In `skip_stateful_validations`, replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy-account** transaction (nonce=0) exists in the pool for the sender address. The mempool should expose a dedicated `deploy_account_in_pool(address)` query, or the existing check should be narrowed to only match deploy-account transaction types.

**Long term:** Add a gateway-level integration test that submits a deploy-account followed by an invoke with an invalid signature and asserts the invoke is rejected. Consider adding a Semgrep rule that flags any code path where `execution_flags.validate = false` is set based on an external, attacker-influenced condition.

---

### Proof of Concept

```
1. Victim submits deploy_account for address X (class_hash=C, salt=S).
   → Gateway admits it; mempool now has deploy_account(X, nonce=0).
   → account_tx_in_pool_or_recent_block(X) == true.

2. Attacker submits invoke(sender=X, nonce=1, signature=[0xdead, 0xbeef]).
   → Gateway stateful validator:
       account_nonce = get_nonce_from_state(X) == 0   ✓
       validate_nonce: 0 <= 1 <= max_gap              ✓
       validate_by_mempool: nonce not too old          ✓
       skip_stateful_validations:
           tx.nonce() == 1 && account_nonce == 0      ✓
           account_tx_in_pool_or_recent_block(X)      ✓  (victim's deploy_account)
           → returns true (skip __validate__)
       run_validate_entry_point(skip_validate=true):
           execution_flags.validate = false
           StatefulValidator::perform_validations → returns Ok(()) without calling __validate__
   → Attacker's invoke admitted to mempool with invalid signature.

3. If fee_escalation enabled and attacker's tip > victim's nonce-1 invoke tip:
   → Attacker's invalid invoke replaces victim's legitimate invoke.
   → Victim's invoke is evicted from mempool.

4. Batcher executes block:
   → deploy_account(X, nonce=0) succeeds; X is now deployed.
   → invoke(X, nonce=1, sig=[0xdead,0xbeef]) executed with validate=true (new_for_sequencing).
   → __validate__ called → fails (invalid signature) → transaction rejected.
   → Victim's legitimate invoke is gone; victim must resubmit.
```

### Citations

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
