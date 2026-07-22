### Title
Signature Validation Bypass via `skip_stateful_validations` Allows Injection of Unauthorized Invoke Transactions into Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point for invoke transactions with nonce=1 when the on-chain account nonce is 0 and the sender address has *any* transaction in the mempool. An attacker who observes a victim's pending `deploy_account` transaction can immediately submit an invoke transaction from the victim's address with a garbage signature, bypassing all signature verification. The gateway admits the invalid transaction into the mempool, blocking the victim's legitimate nonce=1 invoke.

---

### Finding Description

`skip_stateful_validations` is a UX feature: when a user submits `deploy_account` (nonce=0) and `invoke` (nonce=1) together, the gateway accepts the invoke even though the account is not yet deployed on-chain, by skipping the `__validate__` entry point.

The skip condition is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [1](#0-0) 

The third condition — `account_tx_in_pool_or_recent_block(tx.sender_address())` — checks whether **any** transaction from the sender address exists in the mempool. It does **not** verify that the entity submitting the invoke is the same entity who submitted the `deploy_account`. The mempool indexes `deploy_account` transactions under their `contract_address` (the address being deployed):

```rust
pub fn contract_address(&self) -> ContractAddress {
    match &self.tx {
        InternalRpcTransactionWithoutTxHash::DeployAccount(tx) => tx.contract_address,
        ...
    }
}
``` [2](#0-1) 

So when victim V submits `deploy_account` for address V, the mempool records address V as having a pending transaction. Any attacker who then submits an `invoke` with `sender_address = V`, `nonce = 1`, and a garbage signature will satisfy all three conditions:

1. `tx.nonce() == 1` ✓  
2. `account_nonce == 0` (V not yet deployed on-chain) ✓  
3. `account_tx_in_pool_or_recent_block(V) == true` (victim's `deploy_account` is in pool) ✓

The gateway then sets `validate = false` and calls `run_validate_entry_point` without invoking `__validate__`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

The attacker's transaction — with an arbitrary signature and arbitrary calldata — is accepted into the mempool. When the victim subsequently tries to submit their own legitimate invoke with nonce=1, the mempool rejects it as a duplicate nonce.

The older Python-based sequencer (`PyValidator.should_run_stateful_validations`) used a stronger guard: it required the caller to explicitly supply the `deploy_account_tx_hash`, tying the skip to a specific deploy transaction submitted by the same user:

```rust
let deploy_account_not_processed =
    deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
``` [4](#0-3) 

The new Rust gateway replaced this with the weaker `account_tx_in_pool_or_recent_block` check, introducing the vulnerability.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can inject a transaction with a garbage signature from any victim address that has a pending `deploy_account`. The invalid transaction occupies the victim's nonce=1 slot in the mempool. The victim's legitimate invoke is rejected as a duplicate nonce. The attacker can repeat this attack every time the victim attempts to resubmit, causing a persistent denial-of-service on the victim's account for all post-deploy transactions.

The batcher will eventually reject the attacker's transaction when `__validate__` fails during execution (no state changes, no nonce bump), but the victim remains blocked until that block is committed and the rejected transaction is evicted from the mempool.

---

### Likelihood Explanation

The mempool is publicly observable. Any attacker monitoring for `deploy_account` transactions can immediately front-run the victim's nonce=1 invoke. No special privileges, funds, or cryptographic material are required — only the victim's contract address (which is deterministically computable from the `deploy_account` fields) and the ability to submit a transaction to the gateway.

---

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a mechanism that ties the invoke to a specific `deploy_account` transaction submitted by the same user. The simplest fix mirrors the old `PyValidator` approach: require the client to supply the `deploy_account_tx_hash` alongside the invoke, and verify that this hash corresponds to a `deploy_account` in the mempool for the same sender address. Alternatively, perform a lightweight ECDSA signature pre-check at the gateway even when skipping the full `__validate__` entry point, so that only the legitimate key-holder can submit the nonce=1 invoke.

---

### Proof of Concept

**Setup:** Victim V has address `0xVICTIM` (computed from their `class_hash`, `salt`, `constructor_calldata`).

**Step 1 — Victim submits `deploy_account`:**
```
POST /gateway/add_transaction
{
  "type": "DEPLOY_ACCOUNT",
  "nonce": "0x0",
  "class_hash": "0x...",
  "contract_address_salt": "0x...",
  "constructor_calldata": [...],
  "signature": [<valid sig>],
  ...
}
```
The mempool now contains a transaction indexed under `0xVICTIM`.

**Step 2 — Attacker submits invoke from victim's address with garbage signature:**
```
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "0xVICTIM",
  "nonce": "0x1",
  "calldata": [<arbitrary malicious calldata>],
  "signature": ["0xDEAD", "0xBEEF"],   // garbage
  ...
}
```

**Gateway evaluation:**
- `tx.nonce() == 1` ✓
- `account_nonce == 0` (V not on-chain) ✓
- `account_tx_in_pool_or_recent_block(0xVICTIM) == true` (victim's deploy_account is in pool) ✓
- `skip_validate = true` → `__validate__` NOT called → transaction accepted

**Step 3 — Victim submits their own invoke (nonce=1):**
```
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "0xVICTIM",
  "nonce": "0x1",
  "calldata": [<legitimate calldata>],
  "signature": [<valid sig>],
  ...
}
```
**Result:** Rejected — `MempoolError::DuplicateNonce` (attacker's nonce=1 already in pool).

**Step 4 — Batcher processes the block:**
- `deploy_account` (nonce=0) executes successfully; V is deployed.
- Attacker's invoke (nonce=1) reaches `__validate__`; signature check fails; transaction rejected (no state change, no nonce bump).
- Victim can now resubmit nonce=1 — but attacker can repeat Step 2 indefinitely.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L437-456)
```rust
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
```

**File:** crates/starknet_api/src/rpc_transaction.rs (L225-231)
```rust
    pub fn contract_address(&self) -> ContractAddress {
        match &self.tx {
            InternalRpcTransactionWithoutTxHash::Declare(tx) => tx.sender_address,
            InternalRpcTransactionWithoutTxHash::DeployAccount(tx) => tx.contract_address,
            InternalRpcTransactionWithoutTxHash::Invoke(tx) => tx.sender_address,
        }
    }
```

**File:** crates/native_blockifier/src/py_validator.rs (L109-110)
```rust
        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
```
