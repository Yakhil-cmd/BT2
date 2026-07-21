### Title
Invoke Transaction with Nonce=1 Bypasses Gateway `__validate__` Entry-Point When Target Account Has a Pending Deploy-Account in the Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` helper in the gateway's stateful validator returns `true` — suppressing the `__validate__` entry-point call — for any Invoke transaction whose nonce is 1 and whose sender account has nonce 0 in state, provided `account_tx_in_pool_or_recent_block` returns `true` for that address. Because `account_tx_in_pool_or_recent_block` is satisfied by **any** transaction in the pool for that address (not exclusively a `DeployAccount`), an unprivileged attacker who observes a victim's pending `DeployAccount` in the mempool can submit a forged Invoke with nonce=1 and an invalid signature, have it admitted to the mempool without signature verification, and cause it to be sequenced into a block.

---

### Finding Description

**Relevant code — `skip_stateful_validations`** [1](#0-0) 

The function returns `true` when all three conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed in committed state).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`.

**How the skip is applied — `run_validate_entry_point`** [2](#0-1) 

When `skip_validate = true`, `ExecutionFlags { validate: false, … }` is constructed, so the blockifier's `StatefulValidator::validate` call does **not** invoke the account's `__validate__` entry point. The transaction is then forwarded to the mempool without any signature check.

**The overly broad admission check**

The comment at line 441–443 acknowledges the ambiguity:

> "It is sufficient to check if the account exists in the mempool since it means that **either** it has a deploy_account transaction **or** transactions with future nonces that passed validations."

`account_tx_in_pool_or_recent_block` is a single boolean that is `true` for **any** transaction associated with the address — it does not distinguish a `DeployAccount` from an `Invoke`. This means:

- **Attack path A**: Victim submits `DeployAccount` (nonce=0). Attacker observes it in the mempool, then submits `Invoke(nonce=1, signature=garbage)` for the same address. The gateway skips `__validate__` and admits the forged invoke.
- **Attack path B**: Victim has submitted future-nonce invokes (nonces ≥ 2) that are in the pool. Attacker submits `Invoke(nonce=1, signature=garbage)`. Same bypass applies.

**Execution-time consequence**

When the batcher sequences the block it constructs `AccountTransaction` via `new_for_sequencing`, which sets `validate: true`: [3](#0-2) 

So `__validate__` **is** called during actual execution. With an invalid signature the call fails, the transaction reverts, but it is still included in the block. A reverted transaction in Starknet still increments the account nonce and charges fees up to the declared resource bounds.

---

### Impact Explanation

| Effect | Detail |
|---|---|
| **Invalid tx admitted to mempool** | Forged Invoke with wrong signature passes gateway admission — matches High impact "Mempool/gateway/RPC admission accepts invalid transactions." |
| **Nonce disruption** | The reverted Invoke increments the victim's nonce from 1 → 2, permanently invalidating any legitimate Invoke the victim intended to send at nonce=1. |
| **Fee drain** | The victim's newly-deployed account is charged fees for the attacker's reverted transaction (up to the attacker-chosen resource bounds). |
| **Griefing at scale** | Every account that uses the deploy+invoke UX pattern is a target; the attack requires only mempool observation and a single RPC call. |

---

### Likelihood Explanation

- Mempool contents are publicly observable (P2P gossip, RPC `get_pending_transactions`).
- The deploy-account + invoke UX pattern is explicitly supported and documented, so many real users will trigger the vulnerable window.
- The attacker needs no privileged access, no special funds, and no knowledge of the victim's private key.
- The attack is a single `add_transaction` RPC call.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that is specific to `DeployAccount` transactions:

```rust
// Instead of:
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())

// Use a new, narrower API:
mempool_client.has_pending_deploy_account(tx.sender_address())
```

The mempool should expose a method that returns `true` only when a `DeployAccount` transaction for the given address is present in the pool (or was included in a recent block). This preserves the intended UX while closing the bypass for arbitrary Invoke transactions.

---

### Proof of Concept

```
1. Victim submits DeployAccount { sender: 0xVICTIM, nonce: 0, … } → admitted to mempool.

2. Attacker calls add_transaction with:
     InvokeV3 {
       sender_address: 0xVICTIM,
       nonce: 1,
       calldata: [<arbitrary>],
       signature: [0xDEAD, 0xBEEF],   // invalid
       resource_bounds: { l2_gas: { max_amount: 1_000_000, max_price: 1 } }
     }

3. Gateway stateless validation: passes (signature length ≤ max, nonce DA mode = L1, etc.).

4. Gateway stateful validation:
   - account_nonce = get_nonce(0xVICTIM) = 0   (not deployed yet)
   - validate_nonce: nonce=1 is within [0, 0+max_gap] → OK
   - skip_stateful_validations:
       tx.nonce() == 1  ✓
       account_nonce == 0  ✓
       account_tx_in_pool_or_recent_block(0xVICTIM) → true (DeployAccount is in pool)
     → returns true
   - run_validate_entry_point called with validate=false → __validate__ NOT called

5. Attacker's Invoke admitted to mempool alongside victim's DeployAccount.

6. Batcher sequences block:
   - Executes DeployAccount(nonce=0) → account 0xVICTIM deployed.
   - Executes Invoke(nonce=1) with validate=true → __validate__ called → FAILS (bad sig).
   - Transaction reverts; nonce incremented to 2; victim charged fees.

7. Victim's own Invoke(nonce=1) is now rejected: "nonce already used."
```

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
