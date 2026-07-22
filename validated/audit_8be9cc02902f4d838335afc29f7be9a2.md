### Title
Signature Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Admission for Undeployed Accounts — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point call (the only place where a transaction's signature is verified) for any Invoke transaction with `nonce == 1` targeting an account whose on-chain nonce is `0`, provided that `account_tx_in_pool_or_recent_block` returns `true` for that address. Because `account_tx_in_pool_or_recent_block` is a public, address-keyed lookup that returns `true` for **any** address that has ever had a transaction in the pool — including a victim's pending `DeployAccount` — an attacker can submit a forged Invoke transaction (arbitrary calldata, invalid signature) for a victim's not-yet-deployed account and have it admitted to the mempool without any signature check.

### Finding Description

**Relevant code path:**

`add_tx_inner` → `extract_state_nonce_and_run_validations` → `run_pre_validation_checks` → `skip_stateful_validations` → `run_validate_entry_point`

**Step 1 — `skip_stateful_validations` condition:** [1](#0-0) 

The function returns `true` (skip validation) when:
- The transaction is an `Invoke`
- `tx.nonce() == Nonce(Felt::ONE)`
- `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain)
- `account_tx_in_pool_or_recent_block(tx.sender_address())` returns `true`

**Step 2 — `account_tx_in_pool_or_recent_block` is address-only:** [2](#0-1) 

This returns `true` for **any** address that has a transaction in the pool or was seen in a recent committed block. It does not verify that the querying transaction's sender is the same party who submitted the pooled transaction.

**Step 3 — When `skip_validate = true`, `__validate__` is never called:** [3](#0-2) 

`execution_flags.validate` is set to `!skip_validate`. Inside `StatefulValidator::perform_validations`: [4](#0-3) 

If `execution_flags.validate == false`, the function returns `Ok(())` immediately after `perform_pre_validation_stage`, without ever calling the account's `__validate__` entry point. `perform_pre_validation_stage` itself performs only nonce, fee-bound, and proof-facts checks — no signature verification: [5](#0-4) 

**Step 4 — Mempool `validate_tx` also has no signature check:** [6](#0-5) 

`ValidationArgs` carries only `address`, `account_nonce`, `tx_hash`, `tx_nonce`, `tip`, and `max_l2_gas_price` — no signature field. [7](#0-6) 

**Attack scenario:**

1. Victim broadcasts a `DeployAccount` transaction for address `V` (nonce 0). This passes full `__validate_deploy__` validation and enters the mempool.
2. Attacker observes `V` in the mempool via `account_tx_in_pool_or_recent_block`.
3. Attacker crafts an `Invoke` transaction: `sender_address = V`, `nonce = 1`, arbitrary `calldata` (e.g., drain funds), **invalid/random signature**.
4. Gateway stateless validator passes (no signature check).
5. `extract_state_nonce_and_run_validations` fetches on-chain nonce for `V` → `0`.
6. `validate_nonce` passes (nonce 1 is within `max_allowed_nonce_gap`).
7. `validate_by_mempool` passes (no signature check).
8. `skip_stateful_validations` returns `true` (nonce==1, account_nonce==0, `V` is in pool).
9. `run_validate_entry_point` sets `validate = false`; `__validate__` is **never called**.
10. Attacker's forged Invoke is admitted to the mempool at slot `(V, nonce=1)`.
11. Victim's legitimate Invoke with `nonce=1` is rejected with `DuplicateNonce`.

### Impact Explanation

**Matching impact:** *High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

The gateway accepts a transaction with an invalid (attacker-controlled) signature for a victim's account. The victim's own valid transaction for the same nonce is subsequently rejected by the mempool as a duplicate. The attacker's transaction will eventually fail during batcher execution (since `__validate__` is enforced there with default `execution_flags`), but until that block is committed the victim's nonce slot is occupied and their transaction is blocked. With fee escalation disabled (the default), there is no mechanism for the victim to displace the attacker's transaction.

### Likelihood Explanation

The attack requires only:
1. Observing a pending `DeployAccount` transaction for a target address (mempool is public).
2. Submitting a forged Invoke before the victim submits their own nonce-1 transaction.

No privileged access, no special contract, no prior relationship with the victim is needed. The race window is the entire time the `DeployAccount` is pending in the mempool.

### Recommendation

In `skip_stateful_validations`, replace the address-only `account_tx_in_pool_or_recent_block` check with a check that verifies a **`DeployAccount` transaction specifically for `tx.sender_address()`** is pending — not merely that any transaction from that address exists. Alternatively, require that the incoming Invoke transaction's `tx_hash` is pre-authorized (e.g., signed alongside the `DeployAccount`), or simply always run `__validate__` and let the blockifier's `strict_nonce_check = false` handle the ordering leniency without skipping signature verification.

### Proof of Concept

```
1. Victim submits DeployAccount for address V (class_hash C, salt S).
   → Mempool now contains (V, nonce=0, DeployAccount).
   → account_tx_in_pool_or_recent_block(V) == true.

2. Attacker submits Invoke:
     sender_address = V
     nonce          = 1
     calldata       = [transfer_all_to_attacker]
     signature      = [0xdeadbeef]   ← invalid

3. Gateway flow:
   stateless_validate(tx)                    → OK (no sig check)
   convert_rpc_tx_to_internal(tx)            → OK (hash computed, sig not verified)
   get_nonce_from_state(V)                   → 0
   validate_nonce(nonce=1, account_nonce=0)  → OK (within gap)
   validate_by_mempool(...)                  → OK (no sig check)
   skip_stateful_validations(...)            → true  ← KEY
   run_validate_entry_point(skip=true)       → validate=false → __validate__ NOT called
   mempool.add_tx(...)                       → OK

4. Victim submits legitimate Invoke(V, nonce=1, valid_sig):
   mempool.validate_tx(...)  → Err(DuplicateNonce { address: V, nonce: 1 })
   → Victim's transaction REJECTED.
``` [1](#0-0) [3](#0-2) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-315)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-96)
```rust
    pub fn perform_validations(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        // Deploy account transaction should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        // Declare transaction should also be fully executed - otherwise, if we only go through
        // the validate phase, we would miss the check that the class was not declared before.
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
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
        }
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

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L72-83)
```rust
impl From<&AddTransactionArgs> for ValidationArgs {
    fn from(args: &AddTransactionArgs) -> Self {
        Self {
            address: args.tx.contract_address(),
            account_nonce: args.account_state.nonce,
            tx_hash: args.tx.tx_hash(),
            tx_nonce: args.tx.nonce(),
            tip: args.tx.tip(),
            max_l2_gas_price: args.tx.resource_bounds().l2_gas.max_price_per_unit,
        }
    }
}
```
