### Title
Gateway Admits Invoke Transactions with Unverified Signatures via `skip_stateful_validations` UX Bypass — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the blockifier `__validate__` entry-point call — and therefore all account-level signature verification — for any Invoke V3 transaction whose nonce equals 1 and whose sender account has a transaction in the mempool or a recent block. An unprivileged attacker who pre-funds the target account address can exploit this to inject an Invoke transaction carrying an arbitrary (invalid) signature into the mempool, bypassing the only cryptographic admission gate.

---

### Finding Description

**Exact code path:**

`StatefulTransactionValidator::extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which calls `skip_stateful_validations`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:429-460
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

When this returns `true`, `run_validate_entry_point` sets `validate: false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:310-312
let strict_nonce_check = false;
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

Inside `StatefulValidator::perform_validations`, when `validate == false` for an Invoke transaction, execution returns immediately after `perform_pre_validation_stage` — the `__validate__` entry point is never called:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs:76-81
ApiTransaction::Invoke(_) => {
    let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    if !tx.execution_flags.validate {
        return Ok(());   // ← signature check never reached
    }
    // `__validate__` call.
```

`perform_pre_validation_stage` only checks nonce ordering (non-strict), fee bounds, and proof facts — it does **not** verify the account signature.

The `validate_by_mempool` call that precedes `skip_stateful_validations` also performs no signature check; `ValidationArgs` carries only `address`, `account_nonce`, `tx_hash`, `tx_nonce`, `tip`, and `max_l2_gas_price`.

**Trigger conditions (all attacker-controlled):**

| Condition | Attacker action |
|---|---|
| Invoke tx nonce == 1 | Set `nonce = 1` in the submitted tx |
| Account on-chain nonce == 0 | Target any not-yet-deployed account |
| `account_tx_in_pool_or_recent_block` == true | Wait for victim's `deploy_account` to enter the mempool |
| Balance check passes | Pre-fund the deterministic account address with STRK |

The account address is fully deterministic from public fields (`class_hash`, `salt`, `constructor_calldata`), so the attacker can compute it and fund it before the victim's `deploy_account` is submitted.

---

### Impact Explanation

The gateway admits an Invoke transaction carrying an **arbitrary, attacker-chosen signature** into the mempool without any cryptographic verification. This directly violates the admission invariant: every transaction in the mempool must either carry a valid account signature or be provably exempt.

Concrete consequences:

1. **Mempool pollution / DoS**: The attacker can flood the mempool with invalid-signature Invoke transactions for any account whose `deploy_account` is pending, consuming mempool capacity and delaying legitimate transactions.
2. **Block space waste**: The batcher will pull these transactions, include them in a block, and execute them. The `__validate__` entry point will then be called during actual execution (with `validate=true`), the signature check will fail, and the transaction will revert — consuming block bouncer resources without legitimate economic justification.
3. **Fee-loss griefing**: Because the attacker pre-funded the account, the reverted transaction's fee is charged from that balance, but the attacker controls the timing and can craft the attack to maximise disruption relative to cost.

Impact category: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

- No privileged access is required.
- The account address is deterministic and publicly computable.
- The mempool is observable (P2P propagation).
- The only cost to the attacker is the STRK needed to pre-fund the target address to satisfy `verify_can_pay_committed_bounds`; this is a small, bounded amount equal to `max_l2_gas_amount × max_price_per_unit`.
- The stateless validator enforces non-zero resource bounds, so `charge_fee=true` and the balance check is always active — but this is easily satisfied by the attacker's pre-funding step.

---

### Recommendation

1. **Restrict the skip to the legitimate UX case only**: Instead of checking `account_tx_in_pool_or_recent_block` (which matches any account with any pending tx), verify that the mempool contains a `deploy_account` transaction specifically for the sender address. This prevents an attacker from exploiting an account whose `deploy_account` was submitted by a third party.

2. **Alternatively, perform a lightweight signature pre-check**: Before skipping the full `__validate__` call, verify the ECDSA signature against the transaction hash using the class hash declared in the pending `deploy_account` transaction. This preserves the UX benefit while closing the admission gap.

3. **Add a test case**: Add a test that submits an Invoke with nonce=1 and an invalid signature for an account whose `deploy_account` is in the mempool, and asserts that the gateway rejects it.

---

### Proof of Concept

```
1. Observe the mempool for a deploy_account tx for address X
   (class_hash=C, salt=S, constructor_calldata=D → address X is deterministic).

2. Send STRK to address X (e.g., 1 STRK) via a normal invoke from a funded account.
   Wait for this funding tx to be included in a block.

3. Craft an Invoke V3 tx:
     sender_address = X
     nonce          = 1
     calldata       = <arbitrary malicious calldata>
     signature      = [0x1337, 0xdead]   ← completely invalid
     resource_bounds = { l2_gas: { max_amount: 1_000_000,
                                   max_price_per_unit: 1_000_000_000 } }

4. Submit the tx to the gateway.

5. Gateway flow:
   a. stateless_tx_validator.validate() → passes (non-zero bounds, valid address, etc.)
   b. convert_rpc_tx_to_internal_rpc_tx() → computes tx_hash with chain_id → passes
   c. extract_state_nonce_and_run_validations():
      - get_nonce(X) → 0  (account not deployed yet)
      - validate_state_preconditions: nonce 1 ≥ 0 → OK; balance ≥ max_fee → OK (funded)
      - validate_by_mempool: nonce/tip/gas checks → OK
      - skip_stateful_validations: nonce==1, account_nonce==0,
        account_tx_in_pool_or_recent_block(X)==true → returns true
      - run_validate_entry_point(skip_validate=true):
        execution_flags.validate = false
        perform_pre_validation_stage → OK
        __validate__ NOT called  ← invalid signature never checked
      → returns Ok(account_nonce=0)
   d. mempool_client.add_tx() → tx with invalid signature is now in the mempool.

6. Batcher pulls the tx, includes it in a block.
   deploy_account(X) executes first (nonce 0), deploying the account.
   invoke(X, nonce=1) executes next: __validate__ is called, signature fails → revert.
   Fee is charged from X's balance (attacker's pre-funded STRK).
```

The invalid-signature Invoke transaction was admitted to the mempool and included in a block, violating the gateway's admission invariant. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L49-69)
```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
```
