No vulnerability found for this question.

**Reasoning:**

The binding invariant in `verify_signed_message` requires `auth_key == expected_auth_key`, where `expected_auth_key` is computed via `multi_ed25519::unvalidated_public_key_to_authentication_key` → `public_key_bytes_to_authentication_key`, which is `sha3_256(pk_bytes || SIGNATURE_SCHEME_ID)` [1](#0-0) . `multi_ed25519::new_unvalidated_public_key_from_bytes` only enforces that the byte length satisfies `num_sub_pks <= MAX_NUMBER_OF_PUBLIC_KEYS` and `len % INDIVIDUAL_PUBLIC_KEY_NUM_BYTES == THRESHOLD_SIZE_BYTES`; it does not truncate, reinterpret, or otherwise transform the bytes before they are hashed to derive the authentication key [2](#0-1) . Consequently, forging an `account_public_key` byte vector that hashes to a target account's real `auth_key` while containing attacker-controlled key material is exactly a SHA3-256 second-preimage attack — not a parsing/encoding logic flaw in the Move code or in the native `native_signature_verify_strict` (which only compares byte-for-byte deserialized keys/signatures against the message, and correctly returns `false` on malformed pubkeys/signatures) [3](#0-2) . There is no "truncated/malformed encoding accepted by `new_unvalidated_public_key_from_bytes`" that bypasses the hash binding — the full byte vector is always hashed as-is, so any collision would require breaking SHA3-256 preimage resistance, which is outside the scope of an admission-layer logic vulnerability.

The formal spec for `verify_signed_message` confirms the abort conditions are gated strictly on this hash equality and scheme validity, with no alternate acceptance path [4](#0-3) .

### Citations

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L1304-1310)
```text
        } else if (account_scheme == MULTI_ED25519_SCHEME) {
            let pubkey = multi_ed25519::new_unvalidated_public_key_from_bytes(account_public_key);
            let expected_auth_key = multi_ed25519::unvalidated_public_key_to_authentication_key(&pubkey);
            assert!(
                auth_key == expected_auth_key,
                error::invalid_argument(EWRONG_CURRENT_PUBLIC_KEY),
            );
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/multi_ed25519.move (L118-135)
```text
    /// Parses the input 32 bytes as an *unvalidated* MultiEd25519 public key.
    ///
    /// NOTE: This function could have also checked that the # of sub-PKs is > 0, but it did not. However, since such
    /// invalid PKs are rejected during signature verification  (see `bugfix_unvalidated_pk_from_zero_subpks`) they
    /// will not cause problems.
    ///
    /// We could fix this API by adding a new one that checks the # of sub-PKs is > 0, but it is likely not a good idea
    /// to reproduce the PK validation logic in Move. We should not have done so in the first place. Instead, we will
    /// leave it as is and continue assuming `UnvalidatedPublicKey` objects could be invalid PKs that will safely be
    /// rejected during signature verification.
    public fun new_unvalidated_public_key_from_bytes(bytes: vector<u8>): UnvalidatedPublicKey {
        let len = bytes.length();
        let num_sub_pks = len / INDIVIDUAL_PUBLIC_KEY_NUM_BYTES;

        assert!(num_sub_pks <= MAX_NUMBER_OF_PUBLIC_KEYS, error::invalid_argument(E_WRONG_PUBKEY_SIZE));
        assert!(len % INDIVIDUAL_PUBLIC_KEY_NUM_BYTES == THRESHOLD_SIZE_BYTES, error::invalid_argument(E_WRONG_PUBKEY_SIZE));
        UnvalidatedPublicKey { bytes }
    }
```

**File:** aptos-move/framework/natives/src/cryptography/multi_ed25519.rs (L128-169)
```rust
fn native_signature_verify_strict(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(arguments.len() == 3);

    let msg = safely_pop_arg!(arguments, Vec<u8>);
    let pubkey = safely_pop_arg!(arguments, Vec<u8>);
    let signature = safely_pop_arg!(arguments, Vec<u8>);

    context.charge(ED25519_BASE)?;

    let num_sub_pks = NumArgs::new((pubkey.len() / ED25519_PUBLIC_KEY_LENGTH) as u64);
    let num_sub_sigs = NumArgs::new((signature.len() / ED25519_SIGNATURE_LENGTH) as u64);

    context.charge(ED25519_PER_PUBKEY_DESERIALIZE * num_sub_pks)?;
    let pk = match multi_ed25519::MultiEd25519PublicKey::try_from(pubkey.as_slice()) {
        Ok(pk) => pk,
        Err(_) => {
            return Ok(smallvec![Value::bool(false)]);
        },
    };

    context.charge(ED25519_PER_SIG_DESERIALIZE * num_sub_sigs)?;
    let sig = match multi_ed25519::MultiEd25519Signature::try_from(signature.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Ok(smallvec![Value::bool(false)]);
        },
    };

    context.charge(
        ED25519_PER_SIG_STRICT_VERIFY * num_sub_sigs
            + ED25519_PER_MSG_HASHING_BASE * num_sub_sigs
            + (ED25519_PER_MSG_BYTE_HASHING * NumBytes::new(msg.len() as u64)).per::<Arg>()
                * num_sub_sigs,
    )?;

    let verify_result = sig.verify_arbitrary_msg(msg.as_slice(), &pk).is_ok();
    Ok(smallvec![Value::bool(verify_result)])
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.spec.move (L785-795)
```text
        aborts_if account_scheme == ED25519_SCHEME &&
            auth_key != ed25519::spec_public_key_bytes_to_authentication_key(account_public_key);

        include account_scheme == MULTI_ED25519_SCHEME ==> multi_ed25519::NewUnvalidatedPublicKeyFromBytesAbortsIf { bytes: account_public_key };
        aborts_if account_scheme == MULTI_ED25519_SCHEME &&
            auth_key != multi_ed25519::spec_public_key_bytes_to_authentication_key(account_public_key);

        include account_scheme == ED25519_SCHEME ==> ed25519::NewSignatureFromBytesAbortsIf { bytes: signed_message_bytes };
        include account_scheme == MULTI_ED25519_SCHEME ==> multi_ed25519::NewSignatureFromBytesAbortsIf { bytes: signed_message_bytes };

        aborts_if account_scheme != ED25519_SCHEME && account_scheme != MULTI_ED25519_SCHEME;
```
