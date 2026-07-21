### Title
Gateway Skips Signature Validation for Invoke Transactions Based on Any Mempool Entry, Not Specifically a `deploy_account` - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function bypasses the `__validate__` entry-point (signature check) for an invoke transaction with nonce=1 when the sender's on-chain nonce is 0, based solely on whether **any** transaction from that address exists in the mempool. An attacker who observes a victim's `deploy_account` transaction in the mempool can submit an invoke transaction with an invalid signature from the victim's undeployed address, have it admitted to the mempool without signature verification, and use fee escalation to displace the victim's legitimate transaction.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` implements a UX feature: when a user submits a `deploy_account` + `invoke(nonce=1)` pair simultaneously, the invoke transaction cannot be validated on-chain (the account doesn't exist yet), so the gateway skips the blockifier `__validate__` call if a deploy_account is "pending." [1](#0-0) 

The guard for skipping is:

```
tx.nonce() == Nonce(Felt::ONE)
  && account_nonce == Nonce(Felt::ZERO)
  && account_tx_in_pool_or_recent_block(tx.sender_address()) == true
```

`account_tx_in_pool_or_recent_block` is implemented as: [2](#0-1) 

which delegates to: [3](#0-2) 

This returns `true` if **any** transaction from the address is in the pool or in the committed/staged state — it does **not** verify that the transaction is specifically a `deploy_account`. The code comment claims this is sufficient ("it means that either it has a deploy_account transaction or transactions with future nonces that passed validations"), but this assumption is broken by the attack below.

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [4](#0-3) 

The blockifier's `StatefulValidator::perform_validations` then returns early without calling `__validate__`: [5](#0-4) 

So the signature is **never checked** for the attacker's transaction.

### Impact Explanation

**Mempool/gateway admission accepts invalid transactions (High):** An attacker can submit an invoke transaction with an arbitrary/invalid signature for any undeployed account address X, as long as X's `deploy_account` transaction is visible in the mempool. The gateway admits the transaction without verifying the signature.

**Economic impact via fee escalation (Critical):** The attacker can set a higher fee than the victim's legitimate nonce=1 invoke transaction. The mempool's fee-escalation logic will replace the victim's transaction with the attacker's. When the batcher executes the block, the deploy_account runs first (deploying X), then the attacker's invoke runs — `__validate__` is now called on the deployed account, the signature check fails, the transaction reverts, and **fees are charged to the victim's account**. The victim's legitimate transaction has been displaced and their funds drained.

### Likelihood Explanation

- The mempool is publicly observable; any pending `deploy_account` transaction is visible.
- The attack window is the time between `deploy_account` submission and block inclusion — typically seconds to minutes.
- No special privileges are required; any unprivileged network participant can submit transactions to the gateway.
- The `deploy_account` + `invoke` UX pattern is explicitly documented and encouraged by the sequencer's integration tests. [6](#0-5) 

### Recommendation

In `skip_stateful_validations`, replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a **`deploy_account`** transaction is pending for the sender address. This requires either:

1. Adding a new mempool API `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type stored in `tx_pool`, or
2. Storing the transaction type alongside the address in `MempoolState` so the gateway can distinguish a pending deploy from a pending invoke.

The current check at line 444–456 of `stateful_transaction_validator.rs` must not treat an arbitrary invoke transaction in the pool as proof that a deploy_account is pending.

### Proof of Concept

```
1. Victim submits deploy_account tx for address X (nonce=0, valid signature).
   → Gateway admits it; tx_pool.contains_account(X) = true.

2. Attacker observes X in the mempool.
   Attacker crafts invoke tx: sender=X, nonce=1, calldata=<arbitrary>, signature=<garbage>,
   fee > victim's invoke tx fee.

3. Gateway processes attacker's invoke tx:
   a. stateless_tx_validator.validate() — passes (address X is valid, resource bounds OK)
   b. validate_state_preconditions():
      - validate_nonce(): nonce=1 >= account_nonce=0, within max_allowed_nonce_gap → OK
      - validate_resource_bounds(): passes
   c. validate_by_mempool(): nonce=1 >= 0, no duplicate hash → OK
   d. skip_stateful_validations():
      - tx.nonce() == 1 ✓
      - account_nonce == 0 ✓
      - account_tx_in_pool_or_recent_block(X) = true ✓  ← victim's deploy_account triggers this
      → returns true (skip validation)
   e. run_validate_entry_point(skip_validate=true):
      - execution_flags.validate = false
      - StatefulValidator::perform_validations() returns Ok(()) without calling __validate__
      → attacker's garbage signature is NEVER checked

4. Attacker's tx is admitted to the mempool.
   Fee escalation replaces victim's legitimate invoke(nonce=1) with attacker's.

5. Batcher executes block:
   - deploy_account(nonce=0) executes → X is deployed, account nonce = 1
   - attacker's invoke(nonce=1) executes → __validate__ is called on deployed X
     → signature check fails → tx REVERTS → fees charged to X's account
   - Victim's legitimate invoke tx is gone; victim's funds are drained.
``` [7](#0-6) [2](#0-1)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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

**File:** crates/apollo_integration_tests/src/utils.rs (L713-726)
```rust
/// Generates a deploy account transaction followed by an invoke transaction from the same account.
/// The first invoke_tx can be inserted to the first block right after the deploy_tx due to
/// the skip_validate feature. This feature allows the gateway to accept this transaction although
/// the account does not exist yet.
pub fn create_deploy_account_tx_and_invoke_tx(
    tx_generator: &mut MultiAccountTransactionGenerator,
    account_id: AccountId,
) -> Vec<RpcTransaction> {
    let undeployed_account_tx_generator = tx_generator.account_with_id_mut(account_id);
    assert!(!undeployed_account_tx_generator.is_deployed());
    let deploy_tx = undeployed_account_tx_generator.generate_deploy_account();
    let invoke_tx = undeployed_account_tx_generator.generate_trivial_rpc_invoke_tx(1);
    vec![deploy_tx, invoke_tx]
}
```
