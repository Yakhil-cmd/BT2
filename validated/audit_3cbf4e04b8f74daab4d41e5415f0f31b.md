### Title
Invoke Transaction with Nonce=1 Bypasses `__validate__` Signature Check via `skip_stateful_validations` — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` UX feature, intended to allow users to submit a `deploy_account + invoke` bundle atomically, can be abused by an unprivileged attacker to inject an invoke transaction carrying an **arbitrary/invalid signature** into the mempool. The attacker only needs to observe a victim's `deploy_account` transaction in the mempool and front-run it with a crafted invoke at nonce=1 for the same address. The gateway admits the invalid invoke without ever calling the account's `__validate__` entry point.

---

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function returns `true` (skip validation) when all three conditions hold:

1. The incoming transaction is an `Invoke` with `nonce == 1`.
2. The account's on-chain nonce is `0` (not yet deployed).
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [2](#0-1) 

**What `account_tx_in_pool_or_recent_block` actually checks** [3](#0-2) 

It returns `true` if the address has **any** transaction in the pool or any committed block tracked by the mempool's internal state — it does **not** verify that the pooled transaction is specifically a `deploy_account`.

**Effect when `skip_validate = true`**

`run_validate_entry_point` sets `execution_flags.validate = false`: [4](#0-3) 

Inside `StatefulValidator::perform_validations`, the blockifier then returns immediately after `perform_pre_validation_stage` without ever calling `__validate__`: [5](#0-4) 

**`validate_by_mempool` does not fill the gap**

`validate_by_mempool` is called before `skip_stateful_validations` and only checks nonce validity, duplicate tx_hash, and fee-escalation rules via `ValidationArgs` — it carries no signature field and performs no cryptographic check: [6](#0-5) [7](#0-6) 

**Attack steps**

1. Victim broadcasts a `deploy_account` transaction for address `A` (nonce=0). It enters the mempool.
2. Attacker observes this. Attacker crafts an `Invoke` transaction for address `A`, nonce=1, with a completely invalid/random signature.
3. Gateway stateful validation: `account_nonce == 0`, `tx.nonce() == 1`, `account_tx_in_pool_or_recent_block(A) == true` → `skip_validate = true`.
4. `run_validate_entry_point` is called with `validate = false`; `perform_pre_validation_stage` (nonce gap, fee bounds, balance) passes; `__validate__` is **never called**.
5. The attacker's invalid invoke is admitted to the mempool and occupies address `A`'s nonce=1 slot.
6. When the batcher later executes the block, `__validate__` **is** called (the skip is gateway-only), the tx reverts, and the victim's legitimate nonce=1 invoke is blocked or must win a fee-escalation race.

---

### Impact Explanation

An invalid transaction — one whose signature would be rejected by the account's own `__validate__` — is accepted by the gateway and inserted into the mempool. This satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

Concrete consequences:
- **Griefing / nonce-slot squatting**: The attacker occupies the victim's nonce=1 slot. The victim must win a fee-escalation race or wait for the invalid tx to be evicted.
- **Mempool pollution at scale**: An attacker monitoring the mempool can submit one invalid invoke per observed `deploy_account`, filling the mempool with transactions that will always revert.
- **Wasted block space**: The batcher includes the invalid tx; it reverts, consuming block gas and bouncer budget.

---

### Likelihood Explanation

- **No privilege required**: Any unprivileged network participant can submit transactions to the gateway.
- **Observable trigger**: `deploy_account` transactions are visible in the public mempool.
- **Trivially automatable**: A bot can watch for `deploy_account` events and immediately submit a crafted invoke.
- **Condition is narrow but reliable**: The three-condition check (`nonce==1`, `account_nonce==0`, `account_tx_in_pool`) is deterministic and easy to satisfy once a `deploy_account` is in the pool.

---

### Recommendation

1. **Restrict the skip to deploy-account-only presence**: Before returning `true`, verify that the pooled transaction for the address is specifically a `deploy_account` (not just any transaction). This requires the mempool to expose a `has_deploy_account_in_pool(address)` query.

2. **Alternatively, require a lightweight signature pre-check at the gateway**: Even when skipping the full `__validate__` execution, perform a stateless ECDSA/Stark-curve check on the transaction hash and signature before admitting the tx to the mempool.

3. **Limit the nonce gap for the skip path**: The current code allows the skip for any nonce=1 invoke when account_nonce=0. Tightening this to require the deploy_account to be the *immediately preceding* pooled transaction for the same address reduces the attack surface.

---

### Proof of Concept

```
# Precondition: victim's deploy_account for address A is in the mempool.
# account_nonce(A) == 0 on-chain.

attacker_invoke = InvokeV3 {
    sender_address: A,          # victim's address
    nonce: 1,
    signature: [0xdeadbeef],    # arbitrary invalid bytes
    resource_bounds: <valid>,
    calldata: <anything>,
    ...
}

POST /gateway/add_transaction  body=attacker_invoke

# Gateway flow:
#   stateless_validator.validate(attacker_invoke)  → OK (no sig check)
#   account_nonce = get_nonce(A) = 0
#   validate_state_preconditions: nonce 1 within [0, 0+max_gap] → OK
#   validate_by_mempool: no dup hash, nonce gap OK → OK
#   skip_stateful_validations:
#       tx.nonce()==1 && account_nonce==0 && account_tx_in_pool(A)==true
#       → returns true
#   run_validate_entry_point(skip_validate=true):
#       execution_flags.validate = false
#       perform_pre_validation_stage passes (fee/balance OK)
#       __validate__ is NOT called
#   → tx admitted to mempool ✓

# Result: attacker_invoke with invalid signature is now in the mempool
# occupying address A's nonce=1 slot.
# Victim's legitimate nonce=1 invoke is rejected with DuplicateNonce
# unless it wins a fee-escalation race.
``` [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-95)
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
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L50-57)
```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
```
