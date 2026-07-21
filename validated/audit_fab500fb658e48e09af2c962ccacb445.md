### Title
Unauthorized Invoke Transaction Bypasses Signature Verification via `skip_stateful_validations` UX Path — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function unconditionally skips the `__validate__` entry point (signature verification) for any invoke transaction with `nonce == 1` when the target account's `deploy_account` transaction is present in the mempool. An unprivileged attacker who observes a victim's `deploy_account` in the mempool can submit an invoke with an arbitrary/invalid signature for the victim's address, have it accepted by the gateway without signature verification, and — if the attacker's tip is higher than the victim's own invoke — have it executed first, charging the victim's account fees for a transaction the victim never authorized and consuming the victim's nonce=1 slot.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

When an invoke transaction satisfies `tx.nonce() == Nonce(Felt::ONE)` and `account_nonce == Nonce(Felt::ZERO)`, the function calls `account_tx_in_pool_or_recent_block` on the mempool. If that returns `true` (i.e., any transaction from that address is in the pool or a recent block), the function returns `true` — meaning "skip validation."

**How `skip_validate=true` propagates:** [2](#0-1) 

`run_validate_entry_point` sets `ExecutionFlags { validate: !skip_validate, ... }`. When `skip_validate=true`, `validate=false`, so `StatefulValidator::perform_validations` reaches the early-return branch: [3](#0-2) 

The `__validate__` entry point — which is the account's signature-verification function — is **never called** at the gateway. The transaction is accepted and forwarded to the mempool.

**The mempool does not check signatures either:**

`validate_by_mempool` only checks nonce ordering: [4](#0-3) [5](#0-4) 

**At execution time, `__validate__` IS called:**

The batcher uses `AccountTransaction::new_for_sequencing` which hardcodes `validate: true, strict_nonce_check: true`: [6](#0-5) 

So the invalid invoke reaches the blockifier with `validate=true`, `__validate__` fails, the transaction **reverts** — but the nonce has already been incremented by `perform_pre_validation_stage` (pre-validation state changes are not rolled back on revert), and the fee is charged to the victim's account. [7](#0-6) 

**The mempool allows competing transactions with the same nonce (fee escalation):** [8](#0-7) 

The mempool's `account_tx_in_pool_or_recent_block` check only verifies address presence, not which transaction "owns" nonce=1. Two transactions with nonce=1 from the same address can coexist; the batcher selects by tip.

**The `max_nonce_for_validation_skip` config parameter is unused in the new gateway path:** [9](#0-8) 

The config field exists but `skip_stateful_validations` never reads it — the nonce=1 check is hardcoded. There is no operator-level switch to disable this bypass.

---

### Impact Explanation

An attacker who monitors the public mempool for `deploy_account` transactions can:

1. Observe victim Alice's `deploy_account` for deterministic address `A` enter the mempool.
2. Submit `invoke(sender=A, nonce=1, calldata=arbitrary, signature=garbage, tip=very_high)` to the gateway.
3. Gateway: `account_nonce=0`, `tx_nonce=1`, `account_tx_in_pool_or_recent_block(A)=true` → `skip_validate=true` → invoke accepted **without signature verification**.
4. Batcher selects attacker's invoke (higher tip) before Alice's valid invoke.
5. Execution: `deploy_account(nonce=0)` succeeds → Alice's nonce becomes 1; attacker's `invoke(nonce=1)` runs → `__validate__` fails → **REVERT** → Alice's nonce becomes 2, Alice's account is charged the (attacker-set) fee.
6. Alice's valid `invoke(nonce=1)` is now rejected as nonce-too-old.

**Corrupted values:** Alice's account nonce is incremented and her balance is debited for a transaction she never signed. Alice's own invoke is permanently stuck.

**Attacker cost:** Zero. The fee is charged to Alice's account. The attacker need not hold any funds.

This matches: **Critical — Invalid or unauthorized Starknet transaction accepted through account validation/signature logic.**

---

### Likelihood Explanation

- The mempool is public; any observer can detect `deploy_account` transactions.
- Starknet account addresses are deterministic and computable from the `deploy_account` fields.
- No special privileges, no funds, and no prior relationship with the victim are required.
- The attack window is the time between Alice's `deploy_account` entering the mempool and being included in a block — typically multiple seconds to minutes.
- The attack is fully automatable.

---

### Recommendation

1. **Bind the skip-validate privilege to the submitter's identity.** The gateway should only skip `__validate__` for an invoke if the same submitter (IP/session or cryptographic identity) also submitted the corresponding `deploy_account`. A third party must never be able to trigger the skip for another account's address.

2. **Alternatively, require the invoke to carry a valid signature even in the skip path.** The skip is a UX convenience to avoid a round-trip; it does not require skipping cryptographic verification entirely. The gateway can still call `__validate__` against the not-yet-deployed account class (the class hash is known from the `deploy_account` transaction).

3. **Expose `max_nonce_for_validation_skip` as an effective gate.** The config field exists but is never read by `skip_stateful_validations`. Wire it in so operators can set it to `0` to disable the bypass entirely.

---

### Proof of Concept

```
// Alice submits simultaneously:
deploy_account(class_hash=C, salt=S, ctor_data=D)   // nonce=0, address A = hash(C,S,D)
invoke(sender=A, nonce=1, calldata=X, sig=valid)

// Attacker observes deploy_account in mempool, computes A:
invoke(sender=A, nonce=1, calldata=drain, sig=0xdeadbeef, tip=10_000_000)
  → gateway: account_nonce=0, tx_nonce=1, account_tx_in_pool_or_recent_block(A)=true
  → skip_stateful_validations returns true
  → run_validate_entry_point called with validate=false
  → __validate__ NOT called
  → transaction accepted into mempool

// Batcher builds block (attacker's tip wins):
1. deploy_account executes → A deployed, nonce(A)=1
2. attacker's invoke executes:
     perform_pre_validation_stage: handle_nonce(A, strict=true) → nonce(A)=2 ✓ (incremented)
     run_or_revert: __validate__(sig=0xdeadbeef) → FAIL → REVERT
     fee charged to A's balance at attacker-chosen tip rate
3. Alice's invoke(nonce=1) → rejected: nonce 1 < account nonce 2
```

Alice's account has been debited an attacker-controlled fee for an unauthorized transaction, and her nonce=1 invoke is permanently invalidated.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L283-295)
```rust
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
```
