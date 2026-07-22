### Title
Gateway Skips `__validate__` Signature Verification for Invoke Transactions When Any Account Transaction Exists in Mempool, Allowing Forged-Signature Admission — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator bypasses the `__validate__` entry-point call (and therefore all signature verification) for any invoke transaction with `nonce == 1` targeting an account whose on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true`. Because `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from that address in the pool — not specifically a `deploy_account` — an attacker who observes a victim's `deploy_account` in the mempool can immediately submit a forged-signature invoke with `nonce = 1` for the victim's address. The gateway admits it to the mempool without ever calling `__validate__`, violating the invariant that every mempool-admitted transaction carries a verified signature.

### Finding Description

**Relevant code path:**

`extract_state_nonce_and_run_validations` (line 158) calls `run_pre_validation_checks`, which calls `skip_stateful_validations`. When that function returns `true`, `run_validate_entry_point` is called with `execution_flags.validate = false` (line 312), so `StatefulValidator::perform_validations` returns `Ok(())` at line 79–81 without ever invoking `__validate__`.

```
skip_stateful_validations returns true when:
  tx is Invoke
  AND tx.nonce() == Nonce(Felt::ONE)
  AND account_nonce == Nonce(Felt::ZERO)
  AND account_tx_in_pool_or_recent_block(sender) == true
```

`account_tx_in_pool_or_recent_block` (line 697–700) is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

It returns `true` if the address has **any** transaction in the pool — including the `deploy_account` itself, or any previously admitted skip-validated invoke. The code comment at line 441–443 claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." But the second branch is circular: a prior skip-validated invoke was admitted **without** passing `__validate__`, so its presence in the pool does not imply a validated signature.

**Attack scenario:**

1. Victim broadcasts `deploy_account` (nonce 0) + `invoke` (nonce 1) together for the UX flow.
2. Attacker observes the `deploy_account` entering the mempool. The victim's `invoke` has not yet been admitted (or the attacker races it).
3. Attacker constructs an `invoke` for the victim's address with `nonce = 1` and an **arbitrary/forged signature**.
4. Gateway checks: `tx.nonce() == 1`, `account_nonce == 0`, `account_tx_in_pool_or_recent_block == true` (victim's `deploy_account` is in pool) → `skip_validate = true`.
5. `run_validate_entry_point` is called with `validate: false`; `__validate__` is never executed; the forged invoke is admitted to the mempool.
6. When the victim's legitimate invoke arrives, the mempool rejects it with `DuplicateNonce` (line 770) because the attacker's forged invoke already occupies `(address, nonce=1)`. The victim must pay a higher fee (fee escalation) or wait for the forged transaction to be evicted.

**At execution time:** `AccountTransaction::new_for_sequencing` (line 147–155) sets `validate: true, strict_nonce_check: true`, so the blockifier **will** call `__validate__` during block building. For a correctly implemented account the forged transaction reverts. However, the admission invariant is already broken: an invalid transaction entered the mempool and displaced a valid one.

### Impact Explanation

The gateway's mempool admission accepts an invoke transaction whose signature has never been verified. This breaks the invariant "every transaction in the mempool has a valid account signature." Concretely:

- An attacker can front-run any user performing the `deploy_account + invoke` UX flow and inject a forged-signature invoke for the victim's address.
- The victim's legitimate invoke is rejected (`DuplicateNonce`) or must escalate fees to replace the forged one.
- The forged transaction consumes a mempool slot, wastes sequencer execution resources, and produces a reverted receipt in the block.
- If fee escalation is disabled (`enable_fee_escalation = false`), the victim's invoke is permanently blocked until the forged transaction is evicted by TTL.

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

- The attack requires only observing the public mempool for `deploy_account` transactions, which is trivially possible.
- The attacker needs to submit before the victim's invoke is admitted — a race condition that is straightforward to win by monitoring the gateway's HTTP endpoint.
- No privileged access, special keys, or on-chain funds are required.
- The `deploy_account + invoke` UX flow is explicitly documented and encouraged (see `create_deploy_account_tx_and_invoke_tx` in integration tests), so the attack surface is actively used.

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** exists for the address in the pool or recent block. The current check conflates "account has any transaction" with "account has a deploy_account," which is only true at the moment the first invoke is submitted. A dedicated `deploy_account_in_pool_or_recent_block(address)` query that inspects the transaction type would close the window.

Alternatively, record a separate set of addresses for which a `deploy_account` has been seen (and not yet committed), and use that set exclusively for the skip-validate decision.

### Proof of Concept

```
1. Victim calls gateway: POST /gateway/add_transaction with deploy_account for address V (nonce=0).
   → deploy_account admitted to mempool. account_tx_in_pool_or_recent_block(V) == true.

2. Attacker calls gateway: POST /gateway/add_transaction with:
     type: invoke
     sender_address: V
     nonce: 1
     signature: [0xdead, 0xbeef]   ← arbitrary forged bytes
     calldata: [<any>]
     resource_bounds: <valid>

3. Gateway stateful validator:
     account_nonce = get_nonce_from_state(V) = 0
     validate_nonce: 0 <= 1 <= 0+max_gap  → OK
     validate_by_mempool: no duplicate nonce yet → OK
     skip_stateful_validations:
       tx.nonce()==1, account_nonce==0,
       account_tx_in_pool_or_recent_block(V)==true  → returns true
     run_validate_entry_point(skip_validate=true):
       execution_flags.validate = false
       StatefulValidator::perform_validations returns Ok(()) at line 79-81
       __validate__ is NEVER called
   → Forged invoke admitted to mempool.

4. Victim calls gateway: POST /gateway/add_transaction with legitimate invoke (nonce=1, correct sig).
   → validate_by_mempool: DuplicateNonce { address: V, nonce: 1 }
   → Rejected.

5. Victim must pay higher fee (fee escalation) or wait for TTL eviction of forged tx.
```

**Key code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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
