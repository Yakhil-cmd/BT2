## Title
Missing `has_remaining` check in `solana_derivable_account::deserialize_abstract_public_key` allows unpicked trailing-byte malleability of the account-binding public key blob - (File: `aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/solana_derivable_account.move`)

### Summary
`solana_derivable_account::deserialize_abstract_public_key` builds a `bcs_stream::BCSStream` over the attacker-supplied `abstract_public_key` bytes, deserializes exactly two `vector<u8>` fields (`base58_public_key`, `domain`), and returns — **without ever calling `bcs_stream::has_remaining`** to confirm the stream was fully consumed. [1](#0-0) 

Every sibling implementation of the same pattern (`sui_derivable_account`, `keyless`, `federated_keyless`, `single_key`, `multi_key`) explicitly asserts `!bcs_stream::has_remaining(&mut stream)` right after deserialization to reject trailing garbage: [2](#0-1) [3](#0-2) 

This is confirmed by the existing regression tests in `sui_derivable_account.move` that specifically exercise "trailing bytes" and expect an abort with `EMALFORMED_DATA`: [4](#0-3) 

No equivalent test or check exists for `solana_derivable_account`.

### Finding Description
The unprivileged input path is: an attacker who owns a real Solana keypair (or any valid `base58_public_key`/`domain` pair with a valid SIWS signature) submits a transaction using the `solana_derivable_account::authenticate` domain-account-abstraction authenticator. The `abstract_public_key` bytes are taken directly from the transaction authenticator (`AbstractAuthenticationData::DerivableV1.abstract_public_key`) and are fully attacker-controlled.

Two places consume these raw bytes:

1. **Address derivation** (admission-time binding), done in native/framework code *before* the dispatch to the Move authenticator: `derive_account_address` hashes `bcs(func_info) || bcs(abstract_public_key_bytes) || scheme_byte` to compute the expected sender address, and the framework asserts that this equals the actual signer address: [5](#0-4) [6](#0-5) 

2. **Message/signature verification** inside `solana_derivable_account::authenticate_auth_data`, which calls `deserialize_abstract_public_key` to *logically* extract `base58_public_key` and `domain`, then uses only those two fields (not the raw bytes) to build the signed message: [7](#0-6) 

Because address derivation (step 1) hashes the *entire raw byte blob* while signature verification (step 2) only cares about the *logically deserialized prefix* (ignoring anything after it, since there's no `has_remaining` check), an attacker can take one valid `(base58_public_key, domain)` pair with one valid signature and append arbitrary trailing bytes to the BCS-encoded `abstract_public_key`. Each distinct suffix:
- produces a **different** derived Aptos account address (step 1's hash changes with any byte difference), so it does not collide with an existing/victim account, but
- is deserialized identically to the original by `deserialize_abstract_public_key` (step 2), which silently drops the trailing bytes, so
- the **same** SIWS signature verifies successfully for every one of these otherwise-distinct addresses.

This breaks the intended invariant that a `(base58_public_key, domain)` identity is authenticator-bound one-to-one with a single Aptos account address; instead a single Solana keypair can validly authenticate as an unbounded number of distinct, freshly-derived Aptos addresses using one signature, by choosing arbitrary padding. This is authenticator/public-key-binding malleability at the account-abstraction admission boundary, matching the "Authenticator parsing, public key binding ... must bind to the intended account set" pivot.

Note: this does **not** allow impersonating a pre-existing/victim account, because that account's address was already fixed by its own (unpadded) `abstract_public_key` bytes at creation, and the padded blob hashes to a different address. The impact is limited to the attacker being able to mint arbitrarily many valid, distinct addresses from one identity/signature, undermining any protocol-level assumption of a canonical 1:1 mapping between a Solana identity and an Aptos account (e.g., sybil-resistance, per-identity allow-lists/airdrops, uniqueness assumptions built by dApps on top of derivable accounts).

### Impact Explanation
Medium: it is an authenticator/public-key-binding integrity bug reachable by any unprivileged party with a normal SIWS-capable wallet, and it violates the documented invariant ("dispatchable function needs to verify that ... derivable_abstract_public_key() is correct identity representing the authenticator ... missing this step would allow impersonation") stated directly in `account_abstraction.move`: [8](#0-7) 
It does not let an attacker forge a signature for an address they don't control or hijack a victim's existing account, since the derived address itself changes with the padding. The primary damage is loss of the 1-identity-to-1-address guarantee for the Solana derivable account scheme.

### Likelihood Explanation
High likelihood of exploitability, low complexity: any attacker who can produce one valid signed SIWS message can trivially construct many variants by BCS-appending arbitrary bytes to the `abstract_public_key` field of the authenticator before submission — no privileged access, leaked key, or pre-existing approval is required.

### Recommendation
Add the same guard used in `sui_derivable_account.move` immediately after deserialization in `solana_derivable_account::deserialize_abstract_public_key` (and, for defense in depth, `deserialize_abstract_signature`):
```move
fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>): (vector<u8>, vector<u8>) {
    let stream = bcs_stream::new(*abstract_public_key);
    let base58_public_key = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
    let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
    assert!(!bcs_stream::has_remaining(&mut stream), EMALFORMED_DATA);
    (base58_public_key, domain)
}
```
Introduce an `EMALFORMED_DATA` error constant consistent with the other derivable-account modules, and add a regression test mirroring `test_deserialize_abstract_public_key_with_trailing_bytes` from `sui_derivable_account.move`.

### Proof of Concept
Move test (pattern mirrors `sui_derivable_account`'s existing trailing-bytes test, which currently has no counterpart for Solana):
```move
#[test]
fun test_solana_deserialize_abstract_public_key_accepts_trailing_bytes() {
    let base58_public_key = b"G56zT1K6AQab7FzwHdQ8hiHXusR14Rmddw6Vz5MFbbmV";
    let domain = b"aptos-labs.github.io";
    let mut abstract_public_key = create_abstract_public_key(utf8(base58_public_key), utf8(domain));
    // Append trailing bytes to simulate malleability
    abstract_public_key.push_back(0xDE);
    abstract_public_key.push_back(0xAD);
    abstract_public_key.push_back(0xBE);
    abstract_public_key.push_back(0xEF);
    // BUG: this does NOT abort, unlike sui_derivable_account's equivalent test which expects EMALFORMED_DATA
    let (public_key, returned_domain) = deserialize_abstract_public_key(&abstract_public_key);
    assert!(public_key == base58_public_key);
    assert!(returned_domain == domain);
}
```
Since `derive_account_address` hashes the full padded byte blob (including the `0xDEADBEEF` suffix), a transaction whose sender is set to the address derived from this padded blob, together with the original valid SIWS signature over `(base58_public_key, domain)`, passes `authenticate_auth_data`'s ed25519 check unmodified while binding to a brand-new address distinct from the unpadded one. [5](#0-4)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/solana_derivable_account.move (L60-66)
```text
    fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>):
    (vector<u8>, vector<u8>) {
        let stream = bcs_stream::new(*abstract_public_key);
        let base58_public_key = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        (base58_public_key, domain)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/solana_derivable_account.move (L133-160)
```text
    fun authenticate_auth_data(
        aa_auth_data: AbstractionAuthData,
        entry_function_name: &vector<u8>
    ) {
        let abstract_public_key = aa_auth_data.derivable_abstract_public_key();
        let (base58_public_key, domain) = deserialize_abstract_public_key(abstract_public_key);
        let digest_utf8 = string_utils::to_string(aa_auth_data.digest()).bytes();

        let public_key_bytes = to_public_key_bytes(&base58_public_key);
        let public_key = new_validated_public_key_from_bytes(public_key_bytes);
        assert!(public_key.is_some(), EINVALID_PUBLIC_KEY);
        let abstract_signature = deserialize_abstract_signature(aa_auth_data.derivable_abstract_signature());
        match (abstract_signature) {
            SIWSAbstractSignature::MessageV1 { signature: signature_bytes } => {
                let message = construct_message(&b"Solana", &base58_public_key, &domain, entry_function_name, digest_utf8);

                let signature = new_signature_from_bytes(signature_bytes);
                assert!(
                    ed25519::signature_verify_strict(
                        &signature,
                        &public_key_into_unvalidated(public_key.destroy_some()),
                        message,
                    ),
                    EINVALID_SIGNATURE
                );
            },
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/sui_derivable_account.move (L113-119)
```text
    fun deserialize_abstract_public_key(abstract_public_key: &vector<u8>): SuiAbstractPublicKey {
        let stream = bcs_stream::new(*abstract_public_key);
        let sui_account_address = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        let domain = bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x));
        assert!(!bcs_stream::has_remaining(&mut stream), EMALFORMED_DATA);
        SuiAbstractPublicKey { sui_account_address, domain }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/common_account_abstractions/sui_derivable_account.move (L423-436)
```text
    #[test]
    #[expected_failure(abort_code = EMALFORMED_DATA)]
    fun test_deserialize_abstract_public_key_with_trailing_bytes() {
        let sui_account_address = b"0x8d6ce7a3c13617b29aaf7ec58bee5a611606a89c62c5efbea32e06d8d167bd49";
        let domain = b"localhost:3001";
        let abstract_public_key = create_abstract_public_key(sui_account_address, domain);
        // Append trailing bytes to simulate griefing attack
        abstract_public_key.push_back(0xDE);
        abstract_public_key.push_back(0xAD);
        abstract_public_key.push_back(0xBE);
        abstract_public_key.push_back(0xEF);
        // This should fail with EMALFORMED_DATA due to trailing bytes
        deserialize_abstract_public_key(&abstract_public_key);
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/keyless.move (L51-56)
```text
    public fun new_public_key_from_bytes(bytes: vector<u8>): PublicKey {
        let stream = bcs_stream::new(bytes);
        let key = deserialize_public_key(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_KEYLESS_PUBLIC_KEY_EXTRA_BYTES));
        key
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account_abstraction.move (L108-116)
```text
    public fun derive_account_address(derivable_func_info: FunctionInfo, abstract_public_key: &vector<u8>): address {
        // using bcs serialized structs here - this allows for no need for separators.
        // Alternative would've been to create unique string, we would need to convert derivable_func_info into string,
        // then authentication_key to hex, and then we need separators as well - like ::
        let bytes = bcs::to_bytes(&derivable_func_info);
        bytes.append(bcs::to_bytes(abstract_public_key));
        bytes.push_back(DERIVABLE_ABSTRACTION_DERIVED_SCHEME);
        from_bcs::to_address(hash::sha3_256(bytes))
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account_abstraction.move (L166-171)
```text
    /// Add dispatchable derivable authentication function, that enables account abstraction via this function.
    /// This means all accounts within the domain can use it to authenticate, without needing an initialization (unlike non-domain AA).
    /// dispatchable function needs to verify two things:
    /// - that signing_data.derivable_abstract_signature() is a valid signature of signing_data.digest() (just like regular AA)
    /// - that signing_data.derivable_abstract_public_key() is correct identity representing the authenticator
    ///   (missing this step would allow impersonation)
```

**File:** aptos-move/framework/aptos-framework/sources/account/account_abstraction.move (L276-279)
```text
        if (signing_data.is_derivable()) {
            assert!(features::is_derivable_account_abstraction_enabled(), error::invalid_state(EDERIVABLE_ACCOUNT_ABSTRACTION_NOT_ENABLED));
            assert!(master_signer_addr == derive_account_address(func_info, signing_data.derivable_abstract_public_key()), error::invalid_state(EINCONSISTENT_SIGNER_ADDRESS));

```
