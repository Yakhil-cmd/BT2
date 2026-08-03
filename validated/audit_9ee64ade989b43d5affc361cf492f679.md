I confirmed the exact code defect described in the question by reading `api/types/src/transaction.rs`.

### Title
Federated-keyless public keys are mislabeled as plain keyless in `SingleKeySignature`→`AccountAuthenticator` conversion - (File: api/types/src/transaction.rs)

### Summary
In the `TryFrom<&SingleKeySignature> for AccountAuthenticator` implementation, the `PublicKey::FederatedKeyless` branch parses the raw bytes with a comment claiming it produces `AnyPublicKey::FederatedKeyless`, but then wraps the result with `AnyPublicKey::keyless(key)` instead of `AnyPublicKey::federated_keyless(key)`. [1](#0-0) 

```rust
PublicKey::Keyless(ref p) => {
    let key = p.value.inner().try_into().context(
        "Failed to parse given public_key bytes as AnyPublicKey::Keyless",
    )?;
    AnyPublicKey::keyless(key)
},
PublicKey::FederatedKeyless(ref p) => {
    let key = p.value.inner().try_into().context(
        "Failed to parse given public_key bytes as AnyPublicKey::FederatedKeyless",
    )?;
    AnyPublicKey::keyless(key)
},
```

### Finding Description
This is a real code/documentation inconsistency: the `FederatedKeyless` branch's error message and intent clearly indicate a `FederatedKeyless`-typed key should be produced, but the constructor call uses `AnyPublicKey::keyless(...)`, so the resulting `SingleKeyAuthenticator` embeds the key material tagged with the `Keyless` variant discriminant rather than `FederatedKeyless`. This path is reached whenever a client submits a transaction via the REST API's JSON-encoded transaction submission using a `SingleKeySignature` whose `public_key` is `PublicKey::FederatedKeyless`.

### Impact Explanation
While the mislabeling is confirmed in the source, its ability to actually compromise sender/signer binding at the transaction admission boundary depends on how `AnyPublicKey`'s scheme discriminant feeds into authentication-key derivation (`AuthenticationKey` = hash of scheme-tagged public key bytes) and account-address binding, performed downstream by the VM prologue in `aptos-types`/Move framework — code I was not able to fully inspect within the remaining tool budget. Because `FederatedKeyless` public keys carry additional binding data (the federated JWK issuer address) that `Keyless` keys do not, mislabeling the scheme is very likely to produce a differently-derived authentication key that will **not** match the sender account's on-chain registered authentication key, causing the transaction's prologue authentication check to reject it rather than admit it as some other account. I could not conclusively verify this end-to-end within this review's scope (I ran out of tool calls before inspecting the `AnyPublicKey`/`AuthenticationKey` derivation code and the exact `FederatedKeylessPublicKey` field layout), so exploitability at the admission boundary (i.e., an attacker actually getting a transaction admitted under someone else's federated-keyless identity, or bypassing the federated-issuer JWK trust check for an already-controlled account) remains unconfirmed.

### Likelihood Explanation
This code path is only reachable through the REST API's JSON transaction submission format (not the BCS-encoded submission path, which is the primary production path and does not go through this API-types conversion code), which limits exposure. The bug is real and deterministic (any JSON-submitted `FederatedKeyless`-signed transaction hits this code), but whether it results in a security-relevant admission bypass versus a functional failure (transaction rejected due to auth-key mismatch) is not established by the evidence gathered here.

### Recommendation
Regardless of exploitability, this is a genuine defect that should be fixed: change `AnyPublicKey::keyless(key)` to `AnyPublicKey::federated_keyless(key)` in the `PublicKey::FederatedKeyless` branch at `api/types/src/transaction.rs:2109-2114` to match the stated intent and the comment already present in the code. This is worth remediating even if it currently manifests only as a functional bug for legitimate federated-keyless users submitting JSON-encoded transactions.

### Proof of Concept
As suggested in the question: construct a `SingleKeySignature` whose `public_key` is `PublicKey::FederatedKeyless(...)` and `signature` is `Signature::Keyless(...)`, run it through `AccountAuthenticator::try_from(&signature)`, and assert on the resulting `SingleKeyAuthenticator`'s `public_key()` — it will report `AnyPublicKey::Keyless` instead of `AnyPublicKey::FederatedKeyless`, confirming the mislabeling at the source level shown above.

**Caveat:** I could not fully verify within this review whether this mislabeling actually results in transaction admission that breaks sender/signer guarantees (vs. being caught by downstream authentication-key/address-binding checks in the VM prologue), because inspecting `AnyPublicKey`'s authentication-key derivation and the `FederatedKeylessPublicKey` struct definition was outside the remaining tool budget. I recommend a follow-up review of `aptos-types::transaction::authenticator` (`AnyPublicKey`, `AuthenticationKey::from(&SingleKeyAuthenticator)`) to confirm end-to-end exploitability before treating this as a confirmed admission-bypass vulnerability.

### Citations

**File:** api/types/src/transaction.rs (L2103-2114)
```rust
                PublicKey::Keyless(ref p) => {
                    let key = p.value.inner().try_into().context(
                        "Failed to parse given public_key bytes as AnyPublicKey::Keyless",
                    )?;
                    AnyPublicKey::keyless(key)
                },
                PublicKey::FederatedKeyless(ref p) => {
                    let key = p.value.inner().try_into().context(
                        "Failed to parse given public_key bytes as AnyPublicKey::FederatedKeyless",
                    )?;
                    AnyPublicKey::keyless(key)
                },
```
