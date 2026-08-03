## Title
Uncapped fee-payer signature count bypasses `MAX_NUM_OF_SIGS` in `TransactionAuthenticator::verify` - (File: types/src/transaction/authenticator.rs)

### Summary
`TransactionAuthenticator::verify` computes the total signature count for the `MAX_NUM_OF_SIGS` cap using only the sender and secondary signers, omitting `fee_payer_signer` entirely. An unprivileged submitter can craft a `FeePayer` transaction where `fee_payer_signer` is a `MultiEd25519`/`MultiKey` authenticator with an arbitrarily large number of internal signatures, and the cap check will never see them.

### Finding Description
The cap check is:
```
let num_sigs: usize = self.sender().number_of_signatures()
    + self.secondary_signers().iter().map(|auth| auth.number_of_signatures()).sum::<usize>();
if num_sigs > MAX_NUM_OF_SIGS { return Err(...) }
``` [1](#0-0) 

`self.sender()` for the `FeePayer` variant returns only the `sender` field, never `fee_payer_signer`: [2](#0-1) 

And `fee_payer_signer` is a distinct, separately-verified field that is not part of `secondary_signers()` either: [3](#0-2) 

`number_of_signatures()` for `MultiEd25519`/`MultiKey` returns the actual signature-vector length, which is attacker-controlled up to whatever BCS/transaction-size limits allow (not bounded by `MAX_NUM_OF_SIGS`): [4](#0-3) 

The `fee_payer_signer` field is only picked up separately via `fee_payer_signer()`/`all_signers()`, which are not used in the cap calculation in `verify()`: [5](#0-4) [6](#0-5) 

This `verify()` is reached during unprivileged transaction admission: `AptosVM::validate_transaction` (used by both the REST-facing `PooledVMValidator` in vm-validator and mempool's parallel validation task) calls `transaction.check_signature()`, which internally goes through `TransactionAuthenticator::verify`. [7](#0-6) [8](#0-7) [9](#0-8) 

### Impact Explanation
Because the fee payer's own signature count is excluded from the `MAX_NUM_OF_SIGS` accounting, an unprivileged sender acting as (or colluding with) the fee payer can submit a `FeePayer` transaction whose `fee_payer_signer` contains far more than `MAX_NUM_OF_SIGS` individual Ed25519/single-key signatures inside a `MultiEd25519`/`MultiKey` authenticator. `verify()` will still attempt to cryptographically verify all of those signatures (each internal signature check happens inside `MultiEd25519Signature::verify`/`MultiKeyAuthenticator::verify`, invoked unconditionally once the cap check passes), meaning the invariant that "no more than `MAX_NUM_OF_SIGS` total signature verifications are performed per transaction" is broken for the fee-payer slot. This corrupts the intended admission-time cost bound and lets a fee-payer's signature-verification cost scale independent of the cap the code believes it is enforcing.

### Likelihood Explanation
The bug is deterministic and requires no privileged key, leaked secret, or pre-existing approval — only the ability to construct and sign a `FeePayer`-authenticated transaction (fee payer and sender can be the same unprivileged account, or a self-sponsored transaction), which is standard unprivileged transaction construction. The condition triggers on every `FeePayer` verification path, since the omission is unconditional.

### Recommendation
Include `fee_payer_signer.number_of_signatures()` in the `num_sigs` computation in `TransactionAuthenticator::verify` (e.g., by using `self.all_signers()` to sum `number_of_signatures()` across sender, secondary signers, and fee payer signer uniformly) so the `MAX_NUM_OF_SIGS` cap covers the fee-payer slot as well.

### Proof of Concept
Construct a `TransactionAuthenticator::FeePayer` where `sender` and `secondary_signers` together are within the cap, but `fee_payer_signer` is a `MultiEd25519` authenticator whose `signature.signatures().len()` alone exceeds `MAX_NUM_OF_SIGS` (32). Call `.verify(&raw_txn)` with all component signatures validly produced over the appropriate `RawTransactionWithData` messages. Because `self.sender().number_of_signatures() + secondary_signers sum` does not include the fee payer's count, `num_sigs > MAX_NUM_OF_SIGS` never triggers, and `verify()` proceeds to validate all fee-payer sub-signatures and returns `Ok(())`, confirming the cap bypass, based on the logic at: [1](#0-0)

### Citations

**File:** types/src/transaction/authenticator.rs (L160-169)
```rust
    pub fn verify(&self, raw_txn: &RawTransaction) -> Result<()> {
        let num_sigs: usize = self.sender().number_of_signatures()
            + self
                .secondary_signers()
                .iter()
                .map(|auth| auth.number_of_signatures())
                .sum::<usize>();
        if num_sigs > MAX_NUM_OF_SIGS {
            return Err(Error::new(AuthenticationError::MaxSignaturesExceeded));
        }
```

**File:** types/src/transaction/authenticator.rs (L179-224)
```rust
            Self::FeePayer {
                sender,
                secondary_signer_addresses,
                secondary_signers,
                fee_payer_address,
                fee_payer_signer,
            } => {
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
            },
```

**File:** types/src/transaction/authenticator.rs (L248-262)
```rust
    pub fn sender(&self) -> AccountAuthenticator {
        match self {
            Self::Ed25519 {
                public_key,
                signature,
            } => AccountAuthenticator::ed25519(public_key.clone(), signature.clone()),
            Self::FeePayer { sender, .. } => sender.clone(),
            Self::MultiEd25519 {
                public_key,
                signature,
            } => AccountAuthenticator::multi_ed25519(public_key.clone(), signature.clone()),
            Self::MultiAgent { sender, .. } => sender.clone(),
            Self::SingleSender { sender } => sender.clone(),
        }
    }
```

**File:** types/src/transaction/authenticator.rs (L317-331)
```rust
    pub fn fee_payer_signer(&self) -> Option<AccountAuthenticator> {
        match self {
            Self::Ed25519 { .. }
            | Self::MultiEd25519 { .. }
            | Self::MultiAgent { .. }
            | Self::SingleSender { .. } => None,
            Self::FeePayer {
                sender: _,
                secondary_signer_addresses: _,
                secondary_signers: _,
                fee_payer_address: _,
                fee_payer_signer,
            } => Some(fee_payer_signer.clone()),
        }
    }
```

**File:** types/src/transaction/authenticator.rs (L373-390)
```rust
    pub fn all_signers(&self) -> Vec<AccountAuthenticator> {
        match self {
            // This is to ensure that any new TransactionAuthenticator variant must update this function.
            Self::Ed25519 { .. }
            | Self::MultiEd25519 { .. }
            | Self::MultiAgent { .. }
            | Self::FeePayer { .. }
            | Self::SingleSender { .. } => {
                let mut account_authenticators: Vec<AccountAuthenticator> = vec![];
                account_authenticators.push(self.sender());
                account_authenticators.extend(self.secondary_signers());
                if let Some(fee_payer_signer) = self.fee_payer_signer() {
                    account_authenticators.push(fee_payer_signer);
                }
                account_authenticators
            },
        }
    }
```

**File:** types/src/transaction/authenticator.rs (L924-934)
```rust
    /// Return the number of signatures included in this account authenticator.
    pub fn number_of_signatures(&self) -> usize {
        match self {
            Self::Ed25519 { .. } => 1,
            Self::MultiEd25519 { signature, .. } => signature.signatures().len(),
            Self::SingleKey { .. } => 1,
            Self::MultiKey { authenticator } => authenticator.signatures.len(),
            Self::NoAccountAuthenticator => 0,
            Self::Abstract { .. } => 0,
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3499-3501)
```rust
        let Ok(txn) = transaction.check_signature() else {
            return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
        };
```

**File:** vm-validator/src/vm_validator.rs (L146-165)
```rust
    fn validate_transaction(&self, txn: SignedTransaction) -> Result<VMValidatorResult> {
        let vm_validator = self.get_next_vm();

        fail_point!("vm_validator::validate_transaction", |_| {
            Err(anyhow::anyhow!(
                "Injected error in vm_validator::validate_transaction"
            ))
        });

        let result = std::panic::catch_unwind(move || {
            let vm_validator_locked = vm_validator.lock().unwrap();

            use aptos_vm::VMValidator;
            let vm = AptosVM::new(&vm_validator_locked.state.environment);
            vm.validate_transaction(
                txn,
                &vm_validator_locked.state.state_view,
                &vm_validator_locked.state,
            )
        });
```

**File:** mempool/src/shared_mempool/tasks.rs (L576-589)
```rust
    let results = par_map_blocking(transactions, num_cpus::get(), {
        let validator = Arc::clone(&smp.validator);
        move |t| {
            let result = validator.read().validate_transaction(t.0.clone());
            // Pre-compute the hash and length on the original transaction before
            // locking mempool. We return `t` so the cached values survive.
            if result.is_ok() {
                t.0.committed_hash();
                t.0.txn_bytes_len();
            }
            (t, result)
        }
    })
    .await;
```
