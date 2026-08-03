No vulnerability found for this question.

**Rationale:**

The parsing code in `TryFrom<&MultiKeySignature> for AccountAuthenticator` does not cross-check a `FederatedKeyless` entry's `jwk_addr`/issuer at JSON-parse time, but this is not a gap in the admission boundary because the actual binding is enforced by two independent mechanisms that both run before/at admission:

1. **Sender/signer binding via authentication key hashing.** The `jwk_addr` is part of the serialized `AnyPublicKey::FederatedKeyless` bytes, and `AuthenticationKey::any_key`/`AuthenticationKey::multi_key` hashes the *entire* public-key-set bytes (including `jwk_addr`) to derive the authentication key/account address [1](#0-0) . An attacker cannot forge an arbitrary `jwk_addr` binding for an account they don't control the auth key/rotation for, since the account's on-chain authentication key must match this hash.

2. **JWK/issuer binding is verified during mempool admission itself, not deferred to block execution.** Mempool's `validate_and_add_transactions` calls `validator.read().validate_transaction(...)` [2](#0-1) , which routes into `AptosVM::validate_transaction` (`VMValidator` impl), which calls `self.validate_signed_transaction(...)` [3](#0-2) . That function collects all keyless authenticators and immediately invokes `keyless_validation::validate_authenticators` [4](#0-3) , which for `AnyKeylessPublicKey::Federated` fetches `FederatedJWKs` at the claimed `jwk_addr` on-chain and fails the JWK lookup/signature verification if it's inconsistent [5](#0-4) .

Because mempool's admission path and the VM's prologue validation are the *same* code path (`VMValidator::validate_transaction` → `validate_signed_transaction` → `keyless_validation::validate_authenticators`), a `FederatedKeyless` entry with a mismatched issuer/`jwk_addr` binding is rejected at mempool admission time, not merely at block execution. This satisfies the review's exit condition: "Reject if vm-validator, mempool, and VM checks already converge correctly" — they do converge here, since mempool literally invokes the VM validator before admitting the transaction.

### Citations

**File:** types/src/transaction/authenticator.rs (L1010-1018)
```rust
    /// Create an authentication key from an AnyPublicKey
    pub fn any_key(public_key: AnyPublicKey) -> AuthenticationKey {
        Self::from_preimage(public_key.to_bytes(), Scheme::SingleKey)
    }

    /// Create an authentication key from multiple AnyPublicKeys
    pub fn multi_key(public_keys: MultiKey) -> AuthenticationKey {
        Self::from_preimage(public_keys.to_bytes(), Scheme::MultiKey)
    }
```

**File:** mempool/src/shared_mempool/tasks.rs (L576-587)
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1921-1934)
```rust
        let keyless_authenticators = aptos_types::keyless::get_authenticators(transaction)
            .map_err(|_| VMStatus::error(StatusCode::INVALID_SIGNATURE, None))?;

        // If there are keyless TXN authenticators, validate them all.
        if !keyless_authenticators.is_empty() && !self.is_simulation {
            keyless_validation::validate_authenticators(
                self.environment().keyless_pvk(),
                self.environment().keyless_configuration(),
                &keyless_authenticators,
                self.features(),
                session.resolver,
                module_storage,
            )?;
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3550-3558)
```rust
        let (counter_label, result) = match self.validate_signed_transaction(
            &mut session,
            module_storage,
            &txn,
            &txn_data,
            &log_context,
            &mut TraversalContext::new(&storage),
            &mut gas_meter,
        ) {
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L246-264)
```rust
            Err(e) => {
                match pk {
                    // 2.a: If this is a federated keyless account; look in `jwk_addr` for JWKs
                    AnyKeylessPublicKey::Federated(fed_pk) => {
                        let federated_jwks =
                            get_federated_jwks_onchain(resolver, &fed_pk.jwk_addr, module_storage)
                                .map_err(|_| {
                                    invalid_signature!(format!(
                                        "Could not fetch federated PatchedJWKs at {}",
                                        fed_pk.jwk_addr
                                    ))
                                })?;
                        // 2.a.i If not found in jwk_addr either, then we fail the validation.
                        get_jwk_for_authenticator(&federated_jwks.jwks, pk.inner_keyless_pk(), sig)?
                    },
                    // 2.b: If this is not a federated keyless account, then we fail the validation.
                    AnyKeylessPublicKey::Normal(_) => return Err(e),
                }
            },
```
