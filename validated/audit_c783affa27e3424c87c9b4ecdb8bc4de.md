No vulnerability found for this question.

**Rationale:** `Ed25519Signature::verify_arbitrary_msg` at `crates/aptos-crypto/src/ed25519/ed25519_sigs.rs:126-140` first checks scalar (`S`) malleability via `check_s_malleability`, then delegates to `public_key.0.verify_strict(message, &self.0)` from `ed25519-dalek`. `verify_strict` is documented and implemented to reject both the `R` signature component and the public key if either lies in a small (torsion) subgroup — the code comment explicitly states this: "ed25519::PublicKey::verify_strict checks that the signature's R-component and the public key are *not* in a small subgroup" [1](#0-0) .

This is corroborated by dedicated property-based tests: `test_publickey_smallorder` constructs a small-order public key and a crafted signature (with `s = 0`) specifically designed to pass the permissive `verify` equation, and confirms that `verify_strict` (and thus `verify_arbitrary_msg`) rejects it [2](#0-1) . The `verify_sig_strict_torsion` test similarly demonstrates that while the permissive `verify` can be fooled by small-subgroup components, `verify_strict` always rejects them [3](#0-2) .

Additionally, at the native/Move layer, `pubkey_validate_internal` performs an explicit `is_small_order()` check when validating keys before use in strict contexts [4](#0-3) , and the deserialization path used for validated keys elsewhere in the codebase also rejects small-order points directly [5](#0-4) .

There is no code path where `verify_strict`'s small-subgroup check is skipped or bypassed for `verify_arbitrary_msg`; the check is unconditional and applies to every call, and is exercised by targeted regression tests. This does not meet the admission-impact bar since no unprivileged input can bind a forged authenticator to an unintended account under this verification path.

### Citations

**File:** crates/aptos-crypto/src/ed25519/ed25519_sigs.rs (L126-140)
```rust
    fn verify_arbitrary_msg(&self, message: &[u8], public_key: &Ed25519PublicKey) -> Result<()> {
        // NOTE: ed25519::PublicKey::verify_strict already checks that the s-component of the signature
        // is not mauled, but does so via an optimistic path which fails into a slower path. By doing
        // our own (much faster) checking here, we can ensure dalek's optimistic path always succeeds
        // and the slow path is never triggered.
        Ed25519Signature::check_s_malleability(&self.to_bytes())?;

        // NOTE: ed25519::PublicKey::verify_strict checks that the signature's R-component and
        // the public key are *not* in a small subgroup.
        public_key
            .0
            .verify_strict(message, &self.0)
            .map_err(|e| anyhow!("{}", e))
            .and(Ok(()))
    }
```

**File:** crates/aptos-crypto/src/unit_tests/ed25519_test.rs (L199-227)
```rust
    #[test]
    fn verify_sig_strict_torsion(idx in 0usize..8usize){
        let message = b"hello_world";

        // Dalek only performs an order check, so this is allowed
        let bad_scalar = Scalar::zero();

        let bad_component_1 = curve25519_dalek::constants::EIGHT_TORSION[idx];
        let bad_component_2 = bad_component_1.neg();

        // compute bad_pub_key, bad_signature
        let bad_pub_key_point = bad_component_1; // we need this to cancel the hashed component of the verification equation

        // we pick an evil R component
        let bad_sig_point = bad_component_2;

        let bad_key = ed25519_dalek::PublicKey::from_bytes(&bad_pub_key_point.compress().to_bytes()).unwrap();
        // This assertion passes because Ed25519PublicKey::TryFrom<&[u8]> no longer checks for small subgroup membership
        prop_assert!(Ed25519PublicKey::try_from(&bad_pub_key_point.compress().to_bytes()[..]).is_ok());

        let bad_signature = ed25519_dalek::Signature::from_bytes(&[
            &bad_sig_point.compress().to_bytes()[..],
            &bad_scalar.to_bytes()[..]
        ].concat()).unwrap();

        // Seek k = H(R, A, M) ≡ 1 [8] so that sB - kA = R <=> -kA = -A <=> k mod order(A) = 0
        prop_assume!(bad_key.verify(&message[..], &bad_signature).is_ok());
        prop_assert!(bad_key.verify_strict(&message[..], &bad_signature).is_err());
    }
```

**File:** crates/aptos-crypto/src/unit_tests/ed25519_test.rs (L461-499)
```rust
    // Test against known small subgroup public keys.
    #[allow(non_snake_case)]
    #[test]
    fn test_publickey_smallorder((R, A, m) in small_order_pk_with_adversarial_message()) {
        let pk_bytes = A.compress().to_bytes();

        // We expect from_bytes to pass in ed25519_dalek, as it does not validate the PK.
        let pk_dalek = ed25519_dalek::PublicKey::from_bytes(&pk_bytes);
        prop_assert!(pk_dalek.is_ok());
        let pk_dalek = pk_dalek.unwrap();

        // We expect from_bytes_unchecked to pass, as it does not validate the PK.
        let pk = Ed25519PublicKey::from_bytes_unchecked(&pk_bytes);
        prop_assert!(pk.is_ok());
        let pk = pk.unwrap();

        // Ensure the order of the PK is small
        prop_assert!(EIGHT_TORSION.len() <= 8);
        prop_assert!(eight_torsion_order(A) <= EIGHT_TORSION.len());

        // Verification checks sB - hA = R. We set s = 0, and we get R + hA = Identity. We set R to
        // be a small order element, and all we have to do is find a message with any hash h such
        // that R + hA = Identity.
        let s = Scalar::zero();

        let sig_bytes : Vec<u8> = [R.compress().to_bytes(), s.to_bytes()].concat();
        let sig_dalek = ed25519_dalek::Signature::from_bytes(&sig_bytes).unwrap();

        // We expect ed25519-dalek verify to succeed
        prop_assert!(pk_dalek.verify(signing_message(&m).unwrap().as_ref(), &sig_dalek).is_ok());

        // We expect ed25519-dalek verify_strict to fail
        prop_assert!(pk_dalek.verify_strict(signing_message(&m).unwrap().as_ref(), &sig_dalek).is_err());

        // We expect our own validation to fail in Ed25519Signature::verify_arbitrary_msg, since it
        // calls ed25519-dalek's verify_strict
        let sig = Ed25519Signature::from_bytes_unchecked(sig_bytes.as_ref()).unwrap();
        prop_assert!(pk.verify_struct_signature(&m, &sig).is_err());
    }
```

**File:** aptos-move/framework/natives/src/cryptography/ed25519.rs (L74-90)
```rust
    // This deserialization only performs point-on-curve checks, so we check for small subgroup below
    // NOTE(Gas): O(1) cost: some arithmetic for converting to (X, Y, Z, T) coordinates
    let point = match CompressedEdwardsY(key_bytes_slice).decompress() {
        Some(point) => point,
        None => {
            return Ok(smallvec![Value::bool(false)]);
        },
    };

    // Check if the point lies on a small subgroup. This is required when using curves with a
    // small cofactor (e.g., in Ed25519, cofactor = 8).
    // NOTE(Gas): O(1) cost: multiplies the point by the cofactor
    context.charge(ED25519_PER_PUBKEY_SMALL_ORDER_CHECK * NumArgs::one())?;
    let valid = !point.is_small_order();

    Ok(smallvec![Value::bool(valid)])
}
```

**File:** third_party/move/move-examples/diem-framework/crates/crypto/src/ed25519.rs (L374-378)
```rust
        // Check if the point lies on a small subgroup. This is required
        // when using curves with a small cofactor (in ed25519, cofactor = 8).
        if point.is_small_order() {
            return Err(CryptoMaterialError::SmallSubgroupError);
        }
```
