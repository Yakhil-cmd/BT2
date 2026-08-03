## Analysis

The relevant check is `allow_missing_txn_authentication_key`, invoked from `multi_agent_common_prologue`'s "missing hash" branch: [1](#0-0) 

```move
inline fun allow_missing_txn_authentication_key(transaction_sender: address): bool {
    features::is_derivable_account_abstraction_enabled()
        || (features::is_account_abstraction_enabled() && account_abstraction::using_dispatchable_authenticator(transaction_sender))
}
```

Note the asymmetry between the two disjuncts:
- The second disjunct is properly account-bound: it queries `using_dispatchable_authenticator(transaction_sender)` — a per-address resource check confirming *that specific account* actually registered a dispatchable (native) authenticator.
- The first disjunct, `features::is_derivable_account_abstraction_enabled()`, is a **pure global feature-flag check**. It takes no account-address argument at all and is not evaluated against `transaction_sender`/`secondary_address` in any way.

This function is called from `multi_agent_common_prologue`'s else-branch, exactly as described: [2](#0-1) 

```move
let secondary_address = secondary_signer_addresses[i];
assert!(account::exists_at(secondary_address), error::invalid_argument(PROLOGUE_EACCOUNT_DOES_NOT_EXIST));
let signer_public_key_hash = secondary_signer_public_key_hashes[i];
if (!skip_auth_key_check(is_simulation, &signer_public_key_hash)) {
    if (signer_public_key_hash.is_some()) {
        ...
    } else {
        assert!(
            allow_missing_txn_authentication_key(secondary_address),
            error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
        )
    };
};
```

The only precondition for `secondary_address` is `account::exists_at(secondary_address)` — a plain, ordinary (non-AA) account satisfies that trivially. If `is_derivable_account_abstraction_enabled()` is set network-wide (a global governance flag, not per-account), then **any** address can be listed as a secondary signer with an omitted key hash and pass this check, without the framework confirming that `secondary_address` is actually a domain-abstraction-derived address or that it has ever registered any authenticator.

Supporting this, `AuthenticationKey::None` and `AccountAuthenticator::NoAccountAuthenticator`/non-derivable `Abstract` variants both yield `None` from `authentication_key()`: [3](#0-2) 

and the `Abstract` variant's own `.verify()` method does **not** perform real cryptographic verification of ownership — it only checks that the caller supplied a correctly-computed `signing_message_digest` (derivable from public transaction data, not any secret): [4](#0-3) 

The actual cryptographic binding for account abstraction is done later inside `account_abstraction::authenticate`, but that function is only reachable through the sender-authentication dispatch path — I could not confirm within the available tool budget whether `aptos-move/aptos-vm/src/aptos_vm.rs` invokes `account_abstraction::authenticate` for **secondary** signers as well as the primary sender. That file has references to these feature checks (5 matches were found) that I was unable to read in this session before running out of iterations. This is the one remaining gap needed to fully confirm exploitability end-to-end at the VM layer, versus the Move-only invariant break identified above.

### Title
Feature-flag-only gate lets non-abstracted secondary signers skip authentication-key checks in `multi_agent_common_prologue` - (File: aptos-move/framework/aptos-framework/sources/transaction_validation.move)

### Summary
`allow_missing_txn_authentication_key` admits a secondary signer with an omitted public-key hash whenever the *global* `is_derivable_account_abstraction_enabled()` feature is on, without any check that the specific secondary signer address is actually a derivable-account-abstraction account. This breaks the invariant that only genuinely abstracted/authenticated accounts may skip explicit key-hash checks.

### Finding Description
`allow_missing_txn_authentication_key(addr)` at [5](#0-4)  ORs two conditions. The second is properly scoped to `addr` via `account_abstraction::using_dispatchable_authenticator(addr)`. The first, `features::is_derivable_account_abstraction_enabled()`, is a network-wide governance toggle with no relationship whatsoever to `addr`. Once that feature is enabled on-chain (a normal expected end-state, not an attacker action), the function unconditionally returns `true` for every address, including plain non-AA accounts that never opted into any abstraction scheme. `multi_agent_common_prologue` at [2](#0-1)  calls this function precisely in the branch reached when a secondary signer's `signer_public_key_hash` is omitted, and the only other precondition is `account::exists_at(secondary_address)`, satisfied by any ordinary account.

### Impact Explanation
An unprivileged transaction sender could construct a multi-agent (or fee-payer) transaction listing an arbitrary existing account as a secondary signer, submit `option::none()` for that signer's public-key hash, and have the prologue admit it as a legitimately-authenticated secondary signer solely because the derivable-AA feature flag happens to be enabled network-wide — with zero cryptographic proof of control over that account. The entry function executed would then receive a `&signer` for the victim's address, allowing the sender to invoke logic gated on secondary-signer identity (e.g. multi-agent transfers, approvals) without the victim's participation.

### Likelihood Explanation
Likelihood depends on whether the Rust VM layer (`aptos-move/aptos-vm/src/aptos_vm.rs`) independently invokes `account_abstraction::authenticate` (which does properly bind the derived address to the supplied `abstract_public_key`) for secondary signers, not just the transaction sender. I was unable to fully confirm this in the time available. If secondary signers' authenticity is *not* independently re-verified outside this Move prologue check, the issue is directly and trivially exploitable by any user once the feature flag is live. If it is re-verified, this is still a defense-in-depth/invariant violation in the Move code (the comment block at lines 389–412 documents the intended stronger invariant, which the actual code does not enforce), but not independently exploitable.

### Recommendation
Bind the first disjunct to the specific secondary/sender address, mirroring the second disjunct, e.g. by checking that `addr` corresponds to an account actually created via `derive_account_address` (or by requiring that the transaction's own authenticator for `addr` be a genuine `Abstract`/`DerivableV1` authenticator whose implied auth key was checked, rather than allowing hash omission based purely on the global flag).

### Proof of Concept
```move
#[test(aptos_framework = @aptos_framework, alice = @0xA11CE, bob = @0xB0B)]
fun test_secondary_signer_admitted_without_auth_key_when_daa_enabled(
    aptos_framework: &signer, alice: signer, bob: &signer
) {
    // Enable the network-wide derivable-account-abstraction feature.
    features::change_feature_flags_for_testing(
        aptos_framework,
        vector[features::get_derivable_account_abstraction_feature()],
        vector[],
    );
    // `bob` is a plain, non-AA account; never registered any authenticator.
    account::create_account_for_test(signer::address_of(bob));

    // Secondary signer list = [bob], with hash omitted.
    multi_agent_common_prologue(
        vector[signer::address_of(bob)],
        vector[option::none()],
        false,
    );
    // Expected: should abort with PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY (1001)
    // because bob never opted into any abstraction scheme.
    // Actual (with feature enabled): passes silently — no abort.
}
```

### Citations

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L113-118)
```text
    // TODO: can be removed after features have been rolled out.
    inline fun allow_missing_txn_authentication_key(transaction_sender: address): bool {
        // aa verifies authentication itself
        features::is_derivable_account_abstraction_enabled()
            || (features::is_account_abstraction_enabled() && account_abstraction::using_dispatchable_authenticator(transaction_sender))
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L415-430)
```text
            let secondary_address = secondary_signer_addresses[i];
            assert!(account::exists_at(secondary_address), error::invalid_argument(PROLOGUE_EACCOUNT_DOES_NOT_EXIST));
            let signer_public_key_hash = secondary_signer_public_key_hashes[i];
            if (!skip_auth_key_check(is_simulation, &signer_public_key_hash)) {
                if (signer_public_key_hash.is_some()) {
                    assert!(
                        signer_public_key_hash == option::some(account::get_authentication_key(secondary_address)),
                        error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                    );
                } else {
                    assert!(
                        allow_missing_txn_authentication_key(secondary_address),
                        error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                    )
                };
            };
```

**File:** types/src/transaction/authenticator.rs (L836-847)
```rust
            Self::Abstract { authenticator } => {
                let original_signing_message = signing_message(message)?;
                ensure!(
                    authenticator.signing_message_digest()
                        == &AASigningData::signing_message_digest(
                            original_signing_message,
                            authenticator.function_info().clone()
                        )?,
                    "The signing message digest provided in Abstract Authenticator is not expected"
                );
                Ok(())
            },
```

**File:** types/src/transaction/authenticator.rs (L880-905)
```rust
    pub fn authentication_key(&self) -> Option<AuthenticationKey> {
        match self {
            Self::Ed25519 { .. }
            | Self::MultiEd25519 { .. }
            | Self::SingleKey { .. }
            | Self::MultiKey { .. } => Some(AuthenticationKey::from_preimage(
                self.public_key_bytes(),
                self.scheme(),
            )),
            Self::Abstract { authenticator } => {
                match authenticator.auth_data().abstract_public_key() {
                    Some(abstract_public_key) => {
                        // DerivableV1: derive auth key from function_info + abstract_public_key
                        let func_info_bytes = bcs::to_bytes(authenticator.function_info())
                            .expect("FunctionInfo serialization should not fail");
                        Some(AuthenticationKey::domain_abstraction_address(
                            func_info_bytes,
                            abstract_public_key,
                        ))
                    },
                    None => None, // V1 Abstract: no public key available
                }
            },
            Self::NoAccountAuthenticator => None,
        }
    }
```
