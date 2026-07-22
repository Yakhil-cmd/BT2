### Title
`skip_stateful_validations` admits unsigned invoke transactions for any address with a pending deploy_account — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point call (i.e., signature verification) for any invoke transaction whose `nonce == 1` when the on-chain account nonce is `0` and *any* transaction for that `sender_address` is present in the mempool or a recent block. Because the presence check is not restricted to a deploy-account submitted by the same sender, an unprivileged attacker can observe a victim's pending `deploy_account` in the mempool and immediately inject an invoke transaction for that address with an arbitrary (invalid) signature, which the gateway will accept without running `__validate__`.

---

### Finding Description

**Invariant broken:** Every invoke transaction admitted to the mempool must either have passed `__validate__` (signature check) or have been submitted by the same party that controls the account being deployed.

**Root cause — `skip_stateful_validations`:**

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
```

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // ← checks only that SOME tx exists for this address
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

When this returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 311-312
```

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

and `StatefulValidator::perform_validations` returns immediately without calling `__validate__`:

```
crates/blockifier/src/blockifier/stateful_validator.rs  lines 79-81
```

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
```

**The missing check (direct analog to the external bug):**

| External bug | Sequencer analog |
|---|---|
| `commitmentLender(_commitmentId)` checks `msg.sender == original lender` | `account_tx_in_pool_or_recent_block` checks that *some* tx exists for `sender_address` |
| Never checks `_commitment.lender == msg.sender` | Never checks that the invoke's signature is valid |
| Attacker sets `lender` to victim's address | Attacker sets `sender_address` to victim's address |

`account_tx_in_pool_or_recent_block` is defined as:

```
crates/apollo_mempool/src/mempool.rs  lines 697-700
```

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

It returns `true` for *any* account that has ever had a transaction in the pool or a recent block — it does not distinguish who submitted the deploy-account, nor does it verify the incoming invoke's signature.

**Attack path:**

1. Alice broadcasts `deploy_account` for address `A` (nonce 0). It enters the mempool.
2. Attacker observes `A` in the mempool (public).
3. Attacker submits `invoke { sender_address: A, nonce: 1, signature: <garbage> }`.
4. Gateway stateless checks pass (valid address range, resource bounds, etc.).
5. `extract_state_nonce_and_run_validations` fetches on-chain nonce for `A` → `0`.
6. `run_pre_validation_checks` → `skip_stateful_validations` returns `true` because nonce==1, account_nonce==0, and `account_tx_in_pool_or_recent_block(A)` is `true`.
7. `run_validate_entry_point` is called with `validate: false` → `__validate__` is **never called**.
8. The invalid invoke is forwarded to the mempool and accepted.

The attacker can repeat step 3 for every new `deploy_account` they observe, continuously injecting unsigned invokes for victim addresses.

---

### Impact Explanation

The gateway admits invalid invoke transactions — ones that would fail `__validate__` at execution time — into the mempool without any signature check. This satisfies the allowed High impact criterion:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

Concrete effects:
- The mempool is polluted with unsigned invokes for victim accounts.
- The batcher wastes execution resources attempting them (they revert at `__validate__` during block building, with state rolled back).
- An attacker can sustain this at low cost (no valid signature required, only a valid address range and resource bounds), creating a sustained DoS against the mempool and batcher for any account undergoing first-time deployment.

---

### Likelihood Explanation

**High.** The mempool is public. Any observer can enumerate pending `deploy_account` transactions and their target addresses. Submitting a crafted invoke requires only a valid address, nonce=1, and minimal resource bounds — no cryptographic material from the victim is needed. The attack is fully unprivileged and requires no special access.

---

### Recommendation

The `skip_stateful_validations` check must be tightened so that it cannot be triggered by a third party for a victim's address. Options:

1. **Restrict to same-submitter:** Require the invoke to carry the hash of the pending `deploy_account` transaction (e.g., in `account_deployment_data` or as a signed field), and verify that