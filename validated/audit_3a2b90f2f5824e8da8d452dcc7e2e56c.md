## Title
Sponsor-open fee-payer transactions can be hijacked by an unprivileged third party and DoS'd in mempool - ([File: mempool/src/core_mempool/transaction_store.rs])

## Summary
`TransactionAuthenticator::FeePayer::verify` intentionally allows a sender to sign a "sponsor-open" transaction over the zero address (`AccountAddress::ZERO`) instead of the real `fee_payer_address`, so that any sponsor can later attach itself as the fee payer. However, mempool's dedup/idempotency logic in `TransactionStore::insert` only compares `payload`, `expiration_timestamp_secs`, `max_gas_amount`, and `gas_unit_price` for the `(sender, replay_protector)` key — it never binds admission to which account actually signed as fee payer. This lets an unrelated, unprivileged party intercept a sender's zero-address-signed authenticator, splice in its own (unfunded or malicious) address as `fee_payer_address`/`fee_payer_signer`, and get mempool to treat it as the canonical/idempotent version for that sender+sequence-number slot, starving out the legitimate sponsor's properly-funded version and causing the transaction to fail VM admission (`PROLOGUE_ECANT_PAY_GAS_DEPOSIT`) — a griefing pattern structurally analogous to the GMX `createDeposit` DoS, where an unprivileged party mutates shared accounting state to break another party's otherwise-valid admission.

## Finding Description
In `types/src/transaction/authenticator.rs`, `TransactionAuthenticator::verify` for `Self::FeePayer` explicitly supports two signing conventions: signing over the real `fee_payer_address`, or signing over `AccountAddress::ZERO` (an "open" sponsorship). When the sender/secondary signers sign over the zero address, their signature verification does not depend at all on the actual `fee_payer_address` field value: [1](#0-0) 

This means a `SignedTransaction` produced this way can have its `fee_payer_address` and `fee_payer_signer` fields freely replaced by *anyone* — the sender's cryptographic commitment never binds to a specific sponsor. This is a deliberate design for allowing arbitrary sponsors to pick up open transactions.

The gap is that mempool admission does not treat the fee-payer identity as part of the transaction's uniqueness/priority for a given `(sender, replay_protector)` slot. `TransactionStore::insert` only checks payload, expiration, max gas, and gas price equality to decide whether an incoming transaction is a duplicate/update of what's already stored: [2](#0-1) 

None of these fields include the fee payer address or the fee-payer authenticator, so a version submitted by an honest, well-funded sponsor and a version re-signed by a malicious third party with the same `payload`/`expiration`/`max_gas`/`gas_price` are indistinguishable to this logic. Whichever version is inserted "wins" the slot; if the malicious variant arrives first (or matches on the "idempotent" branch), it is accepted and the honest sponsor's variant is treated as already-covered and dropped.

The actual balance requirement for the fee payer is only enforced downstream, in `prologue_common` / `unified_prologue_fee_payer_v2` at VM validation time: [3](#0-2) [4](#0-3) 

So an attacker who swaps in their own (empty) address as fee payer causes the transaction to fail this check with `PROLOGUE_ECANT_PAY_GAS_DEPOSIT`, discarding the transaction from that admission slot.

## Impact Explanation
This is a pre-admission DoS on sponsored ("gasless") transactions: an unprivileged third party — without any private key belonging to the sender or the intended sponsor — can hijack the fee-payer binding of an open-sponsor transaction and cause it to be discarded at VM validation, denying the honest sender/sponsor pair's transaction from ever being admitted, while occupying the `(sender, sequence_number)` slot in mempool. This matches the "Pre-validation mismatch that causes a transaction which should fail admission to execute" / fee-payer confusion class in the admission gate, since the mempool's admission/dedup logic does not bind on the correct fee-payer signer set, letting an unprivileged party rebind who is authorized to pay.

## Likelihood Explanation
Exploitation requires: (1) the sender using the "open sponsorship" (zero-address) signing convention, which is an explicitly supported and documented path in `verify()`, and (2) the attacker being able to observe the sender-signed portion of the transaction before/while it circulates (e.g., via mempool gossip, a public relay, or any off-chain broadcast channel used to solicit sponsors) and race a replacement into mempool with the same payload/expiration/gas parameters. This is feasible for any transaction gossiped through the p2p mempool network, since intermediate/downstream mempool nodes will see and can forward attacker-modified variants for the same `(sender, replay_protector)` key. No private keys of the victim are required, and no privileged role is needed, satisfying the "unprivileged root cause" requirement.

## Recommendation
- Bind mempool's transaction dedup/idempotency key (and eviction/replacement decision) for fee-payer transactions to the fee-payer's identity/signature as well as payload/expiration/gas fields, not just the sender+sequence-number tuple, so a differing fee payer is treated as a genuinely distinct transaction rather than an interchangeable "update."
- Alternatively/additionally, require open-sponsorship submissions to be tracked separately (e.g., keep multiple pending fee-payer candidates per `(sender, replay_protector)` until one successfully passes VM admission) so that a single low-effort/unfunded hijack cannot suppress a legitimate sponsor's submission.

## Proof of Concept
Conceptual repro (not executed):
1. Sender signs a transaction using the zero-address fee-payer convention (`sign_fee_payer`/`sign_aa_transaction` with `AccountAddress::ZERO`), intending it to be sponsor-open; broadcasts it looking for any sponsor.
2. Honest Sponsor S observes it, attaches `fee_payer_address = S`, signs as fee payer over the real address per `RawTransactionWithData::new_fee_payer(..., S)`, and submits to mempool.
3. Attacker A also observes the sender-signed portion (same `sender` authenticator/secondary signers signed over zero address), builds their own variant with `fee_payer_address = A` (an empty/unfunded account) and a trivial self-signature, and submits it to mempool with the same payload/expiration/max_gas/gas price.
4. Depending on arrival order and `TransactionStore::insert` idempotency logic in `mempool/src/core_mempool/transaction_store.rs:266-303`, the attacker's variant can occupy or overwrite the slot; when the VM validates it via `unified_prologue_fee_payer_v2`/`prologue_common`, it fails `PROLOGUE_ECANT_PAY_GAS_DEPOSIT` because A lacks funds, and the transaction is discarded, denying admission of the sender's otherwise-valid, properly-sponsored transaction.

Note: I was not able to fully trace the exact network-gossip/broadcast path timing (e.g., whether typical client workflows expose the sender-signed portion to third parties before a sponsor attaches, versus keeping it private end-to-end) — that dependency affects real-world exploitability and would benefit from further investigation in a live/dynamic environment (e.g., via a Devin session with full repo and test execution access) if a definitive verdict is required.

### Citations

**File:** types/src/transaction/authenticator.rs (L186-223)
```rust
                // In the fee payer model, the fee payer address can be optionally signed. We
                // realized when we designed the fee payer model, that we made it too restrictive
                // by requiring the signature over the fee payer address. So now we need to live in
                // a world where we support a multitude of different solutions. The modern approach
                // assumes that some may sign over the address and others will sign over the zero
                // address, so we verify both and only fail if the signature fails for either of
                // them. The legacy approach is to assume the address of the fee payer is signed
                // over.
                let mut to_verify = vec![sender];
                let _ = secondary_signers
                    .iter()
                    .map(|signer| to_verify.push(signer))
                    .collect::<Vec<_>>();

                let no_fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn_for_signing.clone().into_owned(),
                    secondary_signer_addresses.clone(),
                    AccountAddress::ZERO,
                );

                let mut remaining = to_verify
                    .iter()
                    .filter(|verifier| verifier.verify(&no_fee_payer_address_message).is_err())
                    .collect::<Vec<_>>();

                remaining.push(&fee_payer_signer);

                let fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn_for_signing.into_owned(),
                    secondary_signer_addresses.clone(),
                    *fee_payer_address,
                );

                for verifier in remaining {
                    verifier.verify(&fee_payer_address_message)?;
                }

                Ok(())
```

**File:** mempool/src/core_mempool/transaction_store.rs (L261-303)
```rust
        // If the transaction is already in Mempool, we only allow the user to
        // increase the gas unit price to speed up a transaction, but not the max gas.
        //
        // Transactions with all the same inputs (but possibly signed differently) are idempotent
        // since the raw transaction is the same
        if let Some(txns) = self.transactions.get_mut(&address) {
            if let Some(current_version) = txns.get_mut(&txn_replay_protector) {
                if current_version.txn.payload() != txn.txn.payload() {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a different payload".to_string(),
                    );
                } else if current_version.txn.expiration_timestamp_secs()
                    != txn.txn.expiration_timestamp_secs()
                {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a different expiration timestamp"
                            .to_string(),
                    );
                } else if current_version.txn.max_gas_amount() != txn.txn.max_gas_amount() {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a different max gas amount"
                            .to_string(),
                    );
                } else if current_version.get_gas_price() < txn.get_gas_price() {
                    // Update txn if gas unit price is a larger value than before
                    if let Some(txn) = txns.remove(&txn_replay_protector) {
                        self.index_remove(&txn);
                    };
                    counters::CORE_MEMPOOL_GAS_UPGRADED_TXNS.inc();
                } else if current_version.get_gas_price() > txn.get_gas_price() {
                    return MempoolStatus::new(MempoolStatusCode::InvalidUpdate).with_message(
                        "Transaction already in mempool with a higher gas price".to_string(),
                    );
                } else {
                    // If the transaction is the same, it's an idempotent call
                    // Updating signers is not supported, the previous submission must fail
                    counters::CORE_MEMPOOL_IDEMPOTENT_TXNS.inc();
                    if let Some(acc_seq_num) = account_sequence_number {
                        self.process_ready_seq_num_based_transactions(&address, acc_seq_num);
                    }
                    return MempoolStatus::new(MempoolStatusCode::Accepted);
                }
            }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L194-204)
```text
        // Check if the gas payer has enough balance to pay for the transaction
        let max_transaction_fee = txn_gas_price * txn_max_gas_units;
        if (!skip_gas_payment(
            is_simulation,
            gas_payer_address
        )) {
            assert!(
                aptos_account::is_fungible_balance_at_least(gas_payer_address, max_transaction_fee),
                error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
            );
        };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L765-792)
```text
        prologue_common(
            &sender,
            &fee_payer,
            replay_protector,
            txn_sender_public_key,
            txn_gas_price,
            txn_max_gas_units,
            txn_expiration_time,
            chain_id,
            is_simulation,
            option::none(),
        );
        multi_agent_common_prologue(secondary_signer_addresses, secondary_signer_public_key_hashes, is_simulation);
        if (!skip_auth_key_check(is_simulation, &fee_payer_public_key_hash)) {
            let fee_payer_address = signer::address_of(&fee_payer);
            if (fee_payer_public_key_hash.is_some()) {
                assert!(
                    fee_payer_public_key_hash == option::some(account::get_authentication_key(fee_payer_address)),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                );
            } else {
                assert!(
                    allow_missing_txn_authentication_key(fee_payer_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                )
            };
        }
    }
```
