No vulnerability found for this question.

**Rationale:**

The claim conflates the storage-commit layer with the transaction-admission layer. `AptosDB`'s writer in `storage/aptosdb/src/db/aptosdb_writer.rs` operates on already-validated, already-executed transaction outputs — it has no role in signature/authenticator verification, which happens far earlier in the pipeline (mempool → `VMValidator::validate_transaction` → VM prologue).

The actual signature-binding logic lives in `AptosVM::validate_transaction`, which is called during mempool admission and again pre-execution: [1](#0-0) 

`check_authenticator_features` only gates unsupported signature *schemes* behind feature flags; it does not perform any cryptographic binding itself: [2](#0-1) 

The actual binding check is `transaction.check_signature()`, which calls `TransactionAuthenticator::verify`, which in turn invokes the underlying signature scheme's `verify(message, public_key)`: [3](#0-2) [4](#0-3) [5](#0-4) 

This is a standard cryptographic signature verification (e.g. Ed25519 `signature.verify(message, public_key)`), which mathematically binds the signature to both the exact message (the `RawTransaction`) and the exact public key. If an attacker mutates the public key field while reusing a previously-observed signature blob, the verification equation will fail because the signature was produced with a different private key than the one corresponding to the substituted public key — there is no "gap" between `check_authenticator_features` and `check_signature`; the latter is unconditionally invoked right after the former on every validation path, and it is exactly the check that would catch this exact mutation (returning `StatusCode::INVALID_SIGNATURE`) as shown at line 3499-3501 above.

The proof-of-concept described in the question (mutate public key, keep signature, expect `INVALID_SIGNATURE`) is not a bug demonstration — it is exactly the expected/correct behavior of `validate_transaction`, confirming the checks work as designed rather than revealing a bypass.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L426-460)
```rust
    fn check_authenticator_features(
        &self,
        authenticator: &TransactionAuthenticator,
    ) -> Result<(), VMStatus> {
        if !self
            .features()
            .is_enabled(FeatureFlag::SINGLE_SENDER_AUTHENTICATOR)
        {
            if let TransactionAuthenticator::SingleSender { .. } = authenticator {
                return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
            }
        }

        let webauthn_enabled = self.features().is_enabled(FeatureFlag::WEBAUTHN_SIGNATURE);
        let slh_dsa_enabled = self
            .features()
            .is_enabled(FeatureFlag::SLH_DSA_SHA2_128S_SIGNATURE);
        if !webauthn_enabled || !slh_dsa_enabled {
            let sk_authenticators = authenticator
                .to_single_key_authenticators()
                .map_err(|_| VMStatus::error(StatusCode::INVALID_SIGNATURE, None))?;
            for auth in &sk_authenticators {
                if !webauthn_enabled && matches!(auth.signature(), AnySignature::WebAuthn { .. }) {
                    return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
                }
                if !slh_dsa_enabled
                    && matches!(auth.signature(), AnySignature::SlhDsa_Sha2_128s { .. })
                {
                    return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
                }
            }
        }

        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3474-3501)
```rust
        if let Err(err) = self.check_authenticator_features(transaction.authenticator_ref()) {
            return VMValidatorResult::error(err.status_code());
        }

        if !self
            .features()
            .is_enabled(FeatureFlag::ALLOW_SERIALIZED_SCRIPT_ARGS)
        {
            if let Ok(TransactionExecutableRef::Script(script)) =
                transaction.payload().executable_ref()
            {
                for arg in script.args() {
                    if let TransactionArgument::Serialized(_) = arg {
                        return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
                    }
                }
            }
        }

        if transaction.payload().is_encrypted_variant()
            && !self.features().is_encrypted_transactions_enabled()
        {
            return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
        }

        let Ok(txn) = transaction.check_signature() else {
            return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
        };
```

**File:** types/src/transaction/mod.rs (L1560-1570)
```rust
    /// Checks that the signature of given transaction. Returns `Ok(SignatureCheckedTransaction)` if
    /// the signature is valid.
    pub fn check_signature(self) -> Result<SignatureCheckedTransaction> {
        self.authenticator.verify(&self.raw_txn)?;
        Ok(SignatureCheckedTransaction(self))
    }

    pub fn verify_signature(&self) -> Result<()> {
        self.authenticator.verify(&self.raw_txn)?;
        Ok(())
    }
```

**File:** types/src/transaction/authenticator.rs (L159-178)
```rust
    /// Return Ok if all AccountAuthenticator's public keys match their signatures, Err otherwise
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
        // For encrypted transactions, signatures are verified over the encrypted form
        // (not the decrypted payload). Convert back to the encrypted variant for signing
        // message reconstruction.
        let raw_txn_for_signing = raw_txn.as_encrypted_variant();
        match self {
            Self::Ed25519 {
                public_key,
                signature,
            } => signature.verify(&raw_txn_for_signing, public_key),
```

**File:** types/src/transaction/authenticator.rs (L821-834)
```rust
    /// Return Ok if the authenticator's public key matches its signature, Err otherwise
    pub fn verify<T: Serialize + CryptoHash>(&self, message: &T) -> Result<()> {
        match self {
            Self::Ed25519 {
                public_key,
                signature,
            } => signature.verify(message, public_key),
            Self::MultiEd25519 {
                public_key,
                signature,
            } => signature.verify(message, public_key),
            Self::SingleKey { authenticator } => authenticator.verify(message),
            Self::MultiKey { authenticator } => authenticator.verify(message),
            Self::NoAccountAuthenticator => bail!("No signature to verify."),
```
