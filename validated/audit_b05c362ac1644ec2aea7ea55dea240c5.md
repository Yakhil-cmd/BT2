### Title
Gateway Admits Unsigned Invoke Transactions for Any Account with a Pending Deploy-Account — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call (the only place where the account's signature is verified) for any invoke transaction whose `nonce == 1` and whose sender address already appears in the mempool. Because the check is keyed on the **sender address** rather than on the identity of the submitter, an attacker can inject an invoke transaction carrying an arbitrary (invalid) signature for any victim account that has a pending `deploy_account` transaction in the mempool, and the gateway will admit it without ever verifying the signature.

---

### Finding Description

The gateway stateful-validation path is:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (nonce range, resource bounds)
       ├─ validate_by_mempool            (nonce + fee-escalation only)
       └─ skip_stateful_validations      ← returns true when conditions met
  └─ run_validate_entry_point(skip_validate=true)
       └─ ExecutionFlags { validate: !skip_validate }  ← validate = false
       └─ StatefulValidator::perform_validations
            └─ if !tx.execution_flags.validate { return Ok(()); }  ← __validate__ never called
```

`skip_stateful_validations` returns `true` when all three conditions hold:

1. The transaction is an `Invoke` transaction.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` **and** `account_tx_in_pool_or_recent_block(tx.sender_address())` returns `true`. [1](#0-0) 

Condition 3 checks only whether the **sender address** has any transaction in the mempool — it does not verify that the submitter is the legitimate owner of that address. When all three conditions are satisfied, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

`StatefulValidator::perform_validations` then returns `Ok(())` immediately without calling `validate_tx` (the `__validate__` entry point): [3](#0-2) 

Neither the stateless validator nor the mempool's `validate_tx` check the signature: [4](#0-3) [5](#0-4) 

**Attack scenario:**

1. Victim (Alice) submits a `deploy_account` transaction (nonce = 0) to the gateway; it enters the mempool.
2. Attacker (Bob) observes Alice's address in the mempool via `account_tx_in_pool_or_recent_block`.
3. Bob crafts an `Invoke V3` transaction with `sender_address = Alice`, `nonce = 1`, arbitrary calldata, and a completely invalid (or empty) signature.
4. The gateway evaluates `skip_stateful_validations`: nonce = 1, account_nonce = 0, Alice is in the mempool → returns `true`.
5. `run_validate_entry_point` is called with `validate = false`; `__validate__` is never executed.
6. Bob's transaction is admitted to the mempool and occupies Alice's nonce-1 slot.

The analog to the external report is exact: `removeCollateralWLpTo` only checked `posCollInfo.ids[_wLp].contains(_tokenId)` when `newWLpAmt == 0` (full removal); here, the gateway only checks the signature when `skip_validate == false` (i.e., when the account is already deployed). In both cases, a caller-supplied identifier (tokenId / sender_address) is accepted without ownership verification under a specific condition.

During actual block execution, `AccountTransaction::new_for_sequencing` sets `validate: true`: [6](#0-5) 

So `__validate__` will be called at execution time and the transaction will fail. However, the damage is already done at the mempool-admission stage.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

- The gateway admits an invoke transaction with an invalid (attacker-controlled) signature for any victim account that has a pending `deploy_account` in the mempool.
- Bob's invalid transaction occupies Alice's nonce-1 slot. Alice's legitimate nonce-1 invoke must fee-escalate to displace it; if Bob sets high fees, Alice's transaction is blocked for the duration of the block.
- The mempool's fee-escalation rules mean the attacker can make displacement arbitrarily expensive.
- At execution time the invalid transaction reverts (nonce not incremented), but the block slot and mempool slot were consumed, causing latency and potential ordering disruption for the victim.

---

### Likelihood Explanation

Any account that submits a `deploy_account` transaction is immediately observable in the mempool via `account_tx_in_pool_or_recent_block`. The attack requires no privileged access, no special contract, and no on-chain funds — only the ability to submit an RPC transaction to the gateway. The triggering condition (nonce = 1, account_nonce = 0, address in mempool) is a normal, expected state for every new account deployment.

---

### Recommendation

In `skip_stateful_validations`, replace the bare `account_tx_in_pool_or_recent_block` check with a check that also verifies the **type** of the transaction already in the mempool for that address is specifically a `deploy_account` transaction (not just any transaction). More robustly, do not skip `__validate__` entirely; instead, run a lightweight signature-format check (e.g., verify the signature is non-empty and well-formed) even when the account is not yet deployed, or defer the full `__validate__` call to a simulated execution against the class hash declared in the `deploy_account` transaction.

At minimum, add a guard:

```rust
// Only skip validation if the pending tx for this address is a deploy_account.
let is_deploy_account_pending = mempool_client
    .get_pending_tx_type(tx.sender_address())
    .await? == Some(TxType::DeployAccount);
if !is_deploy_account_pending {
    return Ok(false);
}
``` [7](#0-6) 

---

### Proof of Concept

```rust
// Pseudocode — gateway integration test
async fn test_exploit_skip_validate_for_victim_account() {
    // Step 1: Alice submits deploy_account (nonce=0); it enters the mempool.
    let alice_deploy = alice_tx_generator.generate_deploy_account();
    gateway.add_tx(alice_deploy).await.unwrap();

    // Step 2: Attacker confirms Alice is in the mempool.
    assert!(mempool.account_tx_in_pool_or_recent_block(alice_address));

    // Step 3: Attacker crafts invoke with Alice's address, nonce=1, garbage signature.
    let attacker_invoke = RpcInvokeTransactionV3 {
        sender_address: alice_address,
        nonce: Nonce(Felt::ONE),
        signature: TransactionSignature(vec![Felt::from(0xDEAD_u64)]), // invalid
        calldata: Calldata(vec![].into()),
        resource_bounds: ValidResourceBounds::create_for_testing_with_high_tip(),
        ..Default::default()
    };

    // Step 4: Gateway accepts it — skip_stateful_validations returns true,
    //         __validate__ is never called, invalid signature is never checked.
    let result = gateway.add_tx(RpcTransaction::Invoke(attacker_invoke)).await;
    assert!(result.is_ok()); // ← invalid tx admitted

    // Step 5: Alice's legitimate nonce=1 invoke must now fee-escalate to displace it.
    let alice_invoke = alice_tx_generator.generate_trivial_rpc_invoke_tx(1);
    // This fails or requires higher fees than the attacker's tx.
    let result = gateway.add_tx(alice_invoke).await;
    // MempoolError::DuplicateNonce or fee-escalation required.
}
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-313)
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L31-54)
```rust
impl StatelessTransactionValidator {
    #[instrument(skip(self), level = Level::INFO)]
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
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
