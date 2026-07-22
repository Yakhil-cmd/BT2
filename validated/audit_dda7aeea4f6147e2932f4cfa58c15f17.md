### Title
Signature Verification Bypassed for Invoke Transactions via `skip_stateful_validations` — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry-point (signature check) for any Invoke transaction with `nonce == 1` submitted against an account whose `deploy_account` is already in the mempool. Because the check is purely address-based and not tied to the submitter's identity, any third party can inject an Invoke with a garbage signature on behalf of a victim's not-yet-deployed account. The gateway admits the transaction without verifying the signature, and the mempool accepts it (potentially displacing the victim's legitimate Invoke via fee escalation). This is the direct Sequencer analog of the `bridgeNft()` frontrunning bug: a destructive action (consuming the victim's nonce slot in the mempool) is taken without verifying that the caller is the rightful owner.

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function returns `true` (skip validation) when all three conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

Condition 4 is satisfied by the presence of *any* transaction for that address in the mempool — including the victim's own `deploy_account`. There is no check that the submitter of the Invoke is the same party who submitted the `deploy_account`.

**Effect on `run_validate_entry_point`**

When `skip_validate = true`, the execution flag `validate` is set to `false`: [2](#0-1) 

Inside `validate_tx`, the first thing checked is this flag: [3](#0-2) 

The `__validate__` entry point — which is the account contract's signature verification — is never called. The transaction is admitted to the mempool with an unverified (potentially garbage) signature.

**Mempool does not verify signatures**

`validate_by_mempool` calls `mempool_client.validate_tx`, which only checks nonce ranges and duplicate transactions: [4](#0-3) 

No signature check occurs here either.

**Fee escalation enables displacement**

The mempool supports fee escalation — a transaction at the same `(address, nonce)` can be replaced if the incoming transaction pays a sufficiently higher tip and gas price: [5](#0-4) 

An attacker can therefore displace the victim's legitimate Invoke (which has a valid signature) by submitting a malicious Invoke with a garbage signature and a higher tip.

**Batcher re-validates, preventing fund theft**

When the batcher executes transactions, it uses `AccountTransaction::new_for_sequencing`, which sets `validate: true`: [6](#0-5) 

The batcher will therefore call `__validate__` during execution. Bob's malicious Invoke will fail validation and be *rejected* (not included in the block as a reverted transaction). The victim's nonce is not permanently consumed. However, the victim's legitimate Invoke has already been evicted from the mempool and must be resubmitted.

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions.**

The gateway admits Invoke transactions with garbage signatures into the mempool. An attacker who monitors the mempool for `deploy_account` transactions can:

1. Identify any account being deployed (address is deterministic from class hash + salt + constructor calldata).
2. Submit a malicious Invoke with `nonce=1`, arbitrary calldata, a garbage signature, and a tip just above the victim's Invoke tip.
3. The gateway skips signature verification (`skip_validate = true`) and the mempool accepts the replacement via fee escalation.
4. The victim's legitimate first Invoke is evicted from the mempool.
5. The batcher rejects the malicious Invoke (bad signature), but the victim must resubmit.
6. The attacker can repeat this indefinitely, creating a targeted DoS against any newly deployed account's first transaction.

Fund theft is not possible because the batcher re-validates with `validate: true`. The broken invariant is: *every transaction admitted to the mempool must have passed signature verification or have a legitimate reason to skip it*. The `skip_stateful_validations` feature breaks this invariant by allowing third-party submissions to bypass signature checks.

### Likelihood Explanation

The attack requires only:
- Monitoring the public mempool for `deploy_account` transactions (trivial).
- Submitting an Invoke with `nonce=1` and a higher tip (trivial, no private key needed).

The victim's account address is deterministic and publicly computable. The attack is fully unprivileged and requires no special access. The `deploy_account + invoke` UX pattern is explicitly documented and encouraged, making it a predictable target.

### Recommendation

The `skip_stateful_validations` check should be tightened so that it cannot be triggered by a third party. Options include:

1. **Require the deploy_account transaction hash**: The Invoke submitter must provide the hash of the `deploy_account` transaction they are pairing with. The gateway verifies this hash exists in the mempool for the same address before skipping validation.
2. **Atomic submission**: Accept `deploy_account + invoke` as a single atomic RPC call, so the gateway can verify both transactions come from the same submitter before skipping validation on the Invoke.
3. **Remove the skip entirely**: Require the `deploy_account` to be confirmed in a block before accepting the paired Invoke. This removes the UX optimization but eliminates the attack surface.

### Proof of Concept

```
1. Alice submits deploy_account(class_hash=C, salt=S, nonce=0, sig=valid_sig)
   → Mempool accepts it. account_tx_in_pool_or_recent_block(Alice) = true.

2. Alice submits invoke(sender=Alice, nonce=1, calldata=[transfer_to_alice], sig=valid_sig)
   → Gateway: skip_stateful_validations returns true (nonce==1, account_nonce==0, Alice in mempool)
   → __validate__ skipped. Admitted to mempool.

3. Bob submits invoke(sender=Alice, nonce=1, calldata=[anything], sig=GARBAGE, tip=Alice_tip * 1.11)
   → Gateway: skip_stateful_validations returns true (same conditions still hold)
   → __validate__ skipped. Garbage signature never checked.
   → Mempool: fee escalation check passes (Bob's tip > Alice's tip by required %).
   → Alice's legitimate invoke is EVICTED. Bob's malicious invoke is now in the mempool.

4. Batcher executes:
   → deploy_account: succeeds. Alice's account is deployed.
   → Bob's invoke: batcher runs __validate__ with validate=true.
     → __validate__ fails (garbage signature). Transaction REJECTED.
   → Alice's nonce stays at 1, but her invoke is gone from the mempool.
   → Alice must resubmit. Bob can repeat step 3 indefinitely.
```

**Affected file:** `crates/apollo_gateway/src/stateful_transaction_validator.rs`, function `skip_stateful_validations` (lines 429–461) and `run_validate_entry_point` (lines 302–356). [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
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

**File:** crates/apollo_mempool/src/mempool.rs (L760-792)
```rust
    fn validate_fee_escalation(
        &self,
        incoming_tx_reference: TransactionReference,
    ) -> MempoolResult<Option<TransactionReference>> {
        let TransactionReference { address, nonce, .. } = incoming_tx_reference;

        self.validate_no_delayed_declare_front_run(incoming_tx_reference)?;

        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
        }

        let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
        else {
            // Replacement irrelevant: no existing transaction with the same nonce for address.
            return Ok(None);
        };

        if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
            info!(
                "{existing_tx_reference} was not replaced by {incoming_tx_reference} due to \
                 insufficient fee escalation."
            );
            // TODO(Elin): consider adding a more specific error type / message.
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }

        Ok(Some(existing_tx_reference))
    }
```
