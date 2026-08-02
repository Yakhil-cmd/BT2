No vulnerability found for this question.

**Analysis:**

`validated_public_key_threshold` at [1](#0-0)  simply reads the last byte of `pk.bytes` as the threshold, and it's true that the deprecated `new_validated_public_key_from_bytes` path can produce a `ValidatedPublicKey` with zero sub-PKs (as reproduced in the existing test `bugfix_validated_pk_from_zero_subpks`) [2](#0-1) . However, this does not translate into an admission-boundary exploit:

1. **No downstream caller exists.** A repo-wide search shows `validated_public_key_threshold` has no callers anywhere in production Move framework or Rust code outside of the `multi_ed25519.move` module's own tests/specs. There is no multisig account, authenticator, or admission-check code that calls this function on an attacker-influenced `ValidatedPublicKey` and trusts the resulting threshold without checking `num_sub_pks`.

2. **The module itself documents why this is safe.** The doc comments explicitly state that PKs with zero sub-PKs "will not cause problems" because `signature_verify_strict_internal` safely rejects such invalid PKs during actual signature verification [3](#0-2) , and the native function doc similarly classifies this as "not a security issue, but a correctness issue" [4](#0-3) . Since no real signature can ever satisfy a 0-sub-PK key, a threshold value paired with zero signers can never actually be used to admit a signed transaction — verification fails deterministically before any threshold comparison could matter.

3. **No admission path uses this deprecated struct.** Transaction admission (mempool/vm-validator/authenticator) for multi-ed25519 accounts operates on raw authenticator bytes and native `signature_verify_strict_internal`/`public_key_validate_internal`, not on Move-level `ValidatedPublicKey` threshold introspection. The `ValidatedPublicKey` type and its accessor functions are unused in any sender/signer-set binding logic.

Since the required chain (unprivileged input → buggy `ValidatedPublicKey` → `validated_public_key_threshold` call → an admission check that trusts the threshold without checking `num_sub_pks > 0` → wrongful transaction admission) does not exist anywhere in the codebase, this does not meet the Admission Impact Gate.

### Citations

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/multi_ed25519.move (L118-127)
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
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/multi_ed25519.move (L271-277)
```text
    /// Returns the number t of sub-PKs in a validated t-out-of-n MultiEd25519 PK (i.e., the threshold).
    public fun validated_public_key_threshold(pk: &ValidatedPublicKey): u8 {
        let len = pk.bytes.length();
        let threshold_byte = pk.bytes[len - 1];

        threshold_byte
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/multi_ed25519.move (L311-316)
```text
    /// DEPRECATED: Use `public_key_validate_internal_v2` instead. This function was NOT correctly implemented:
    ///
    ///  1. It does not check that the # of sub public keys is > 0, which leads to invalid `ValidatedPublicKey` objects
    ///     against which no signature will verify, since `signature_verify_strict_internal` will reject such invalid PKs.
    ///     This is not a security issue, but a correctness issue. See `bugfix_validated_pk_from_zero_subpks`.
    ///  2. It charges too much gas: if the first sub-PK is invalid, it will charge for verifying all remaining sub-PKs.
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/multi_ed25519.move (L366-382)
```text
    #[test(fx = @std)]
    fun bugfix_validated_pk_from_zero_subpks(fx: signer) {
        features::change_feature_flags_for_testing(&fx, vector[ features::multi_ed25519_pk_validate_v2_feature()], vector[]);
        let bytes = vector<u8>[1u8];
        assert!(bytes.length() == 1, 1);

        // Try deserializing a MultiEd25519 `ValidatedPublicKey` with 0 Ed25519 sub-PKs and 1 threshold byte.
        // This would ideally NOT succeed, but it currently does. Regardless, such invalid PKs will be safely dismissed
        // during signature verification.
        let some = new_validated_public_key_from_bytes(bytes);
        assert!(check_and_get_threshold(bytes).is_none(), 1);   // ground truth
        assert!(some.is_some(), 2);                             // incorrect

        // In contrast, the v2 API will fail deserializing, as it should.
        let none = new_validated_public_key_from_bytes_v2(bytes);
        assert!(none.is_none(), 3);
    }
```
