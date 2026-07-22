### Title
Signature Validation Bypass via `skip_stateful_validations` Special Case Admits Unsigned Invoke Transactions — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function omits the `__validate__` entry-point call (which performs signature verification) for any invoke transaction with nonce=1 sent from an account whose nonce is 0, provided `account_tx_in_pool_or_recent_block` returns `true`. The check is satisfied by the presence of **any** transaction for that address in the mempool — not specifically a `deploy_account`. An unprivileged attacker who observes a victim's pending `deploy_account` in the mempool can immediately submit an invoke with nonce=1 and an arbitrary or forged signature, and the gateway will accept it without ever calling `__validate__`. The invalid transaction is admitted to the mempool, occupying the victim's nonce=1 slot and blocking the victim's legitimate first invoke.

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function returns `true` (skip `__validate__`) when all three conditions hold:
1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)`.
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

**The overly broad membership check** [2](#0-1) 

`account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in `tx_pool` or in the committed-nonce state. The code comment in `skip_stateful_validations` claims this implies a `deploy_account` exists, but the implementation imposes no such constraint — a `deploy_account` submitted by the victim is sufficient to satisfy the check.

**How the skip propagates to the blockifier** [3](#0-2) 

When `skip_validate = true`, `execution_flags.validate` is set to `false`, and `StatefulValidator::perform_validations` returns `Ok(())` immediately without calling `validate_tx`: [4](#0-3) 

**Mempool `validate_tx` does not check signatures** [5](#0-4) 

`validate_tx` only checks for duplicate tx hashes and nonce ordering — no signature or account-contract verification. The attacker's transaction passes all mempool checks.

**`ValidationArgs` carries no signature field** [6](#0-5) 

**Execution path re-enables `validate`**

During batcher execution, `AccountTransaction::new_for_sequencing` sets `validate: true`: [7](#0-6) 

So the attacker's transaction will fail `__validate__` and be rejected (not included in a block), but the damage is already done at admission time.

**End-to-end exploit path**

1. Victim broadcasts `deploy_account` (nonce=0) for address X. It enters the mempool; `tx_pool.contains_account(X)` becomes `true`.
2. Attacker submits `Invoke` with `sender_address=X`, `nonce=1`, arbitrary calldata, and an invalid/forged signature.
3. Gateway `validate_nonce`: nonce=1 is within the allowed gap from account_nonce=0 — passes.
4. Gateway `validate_by_mempool`: no duplicate hash, nonce ≥ account_nonce — passes.
5. Gateway `skip_stateful_validations`: all three conditions met, returns `true`.
6. Gateway `run_validate_entry_point` with `skip_validate=true`: `__validate__` is **never called**.
7. Transaction is forwarded to the mempool and accepted.
8. Victim submits their legitimate nonce=1 invoke — rejected as `DuplicateNonce` (fee escalation disabled by default). [8](#0-7) 

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts an invalid (unsigned) transaction before sequencing.**

The gateway's stateful validation is the only place where `__validate__` is called for invoke transactions before they enter the mempool. By triggering the skip, an attacker inserts a signature-less invoke into the mempool for any account that has a pending `deploy_account`. The victim's legitimate first invoke (nonce=1) is blocked with `DuplicateNonce` until the attacker's transaction is eventually rejected by the batcher and the mempool slot is freed. This is a targeted, repeatable griefing attack requiring no privileged access.

### Likelihood Explanation

Any account that broadcasts a `deploy_account` transaction is immediately vulnerable for the window between mempool admission and block commitment. The attack requires only observing the mempool (public) and submitting a crafted invoke — no keys, no privileged access, no special tooling. The default `max_nonce_for_validation_skip = Nonce(Felt::ONE)` and `enable_fee_escalation = false` configuration maximises the impact. [9](#0-8) 

### Recommendation

**Short term:** In `skip_stateful_validations`, replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the sender address in the mempool (e.g., expose a `deploy_account_in_pool(address)` query). This eliminates the ability to trigger the skip by observing any arbitrary pending transaction.

**Long term:** Avoid special-casing authorization checks based on external mutable state (mempool contents). The UX goal (accepting deploy+invoke atomically) can be achieved more safely by having the gateway itself verify that the paired `deploy_account` was submitted in the same batch/request, rather than relying on a mempool membership query that any observer can satisfy.

### Proof of Concept

```
// Precondition: victim has submitted deploy_account for address X (nonce=0),
// which is currently in the mempool.

// Attacker constructs:
let attacker_invoke = InvokeTransactionV3 {
    sender_address: X,          // victim's undeployed address
    nonce: Felt::ONE,           // nonce = 1
    calldata: vec![/* arbitrary: e.g. transfer tokens */],
    signature: vec![Felt::ZERO, Felt::ZERO],  // invalid signature
    // ... resource bounds set to pass stateless checks
};

// POST /gateway/add_transaction with attacker_invoke
// Expected: HTTP 200, transaction accepted

// Victim now submits their legitimate nonce=1 invoke:
// Expected: MempoolError::DuplicateNonce { address: X, nonce: 1 }
// Victim's transaction is blocked until attacker's tx is rejected by batcher.
```

The `test_skip_validate` test in `crates/apollo_gateway/src/stateful_transaction_validator_test.rs` already demonstrates that `should_skip_validation` is `true` when `contains_tx=true` (any tx in mempool), confirming the bypass is reachable with a standard `deploy_account` in the pool. [10](#0-9)

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

**File:** crates/apollo_mempool/src/mempool.rs (L768-773)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
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

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L151-157)
```rust
#[rstest]
#[case::should_skip_validation(
    executable_invoke_tx(invoke_tx_args!(nonce: nonce!(1))),
    nonce!(0),
    true,
    false
)]
```
