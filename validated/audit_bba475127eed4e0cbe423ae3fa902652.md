[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/sui-types/src/signature.rs (L164-173)
```rust
                    SignatureScheme::Secp256r1 | SignatureScheme::PasskeyAuthenticator => {
                        Ok(CompressedSignature::Secp256r1(
                            (&Secp256r1Signature::from_bytes(bytes).map_err(|_| {
                                SuiErrorKind::InvalidSignature {
                                    error: "Cannot parse secp256r1 sig".to_string(),
                                }
                            })?)
                                .into(),
                        ))
                    }
```

**File:** crates/sui-types/src/signature.rs (L196-228)
```rust
    pub fn to_public_key(&self) -> Result<PublicKey, SuiError> {
        match self {
            GenericSignature::Signature(s) => {
                let bytes = s.public_key_bytes();
                match s.scheme() {
                    SignatureScheme::ED25519 => Ok(PublicKey::Ed25519(
                        (&Ed25519PublicKey::from_bytes(bytes).map_err(|_| {
                            SuiErrorKind::KeyConversionError("Cannot parse ed25519 pk".to_string())
                        })?)
                            .into(),
                    )),
                    SignatureScheme::Secp256k1 => Ok(PublicKey::Secp256k1(
                        (&Secp256k1PublicKey::from_bytes(bytes).map_err(|_| {
                            SuiErrorKind::KeyConversionError(
                                "Cannot parse secp256k1 pk".to_string(),
                            )
                        })?)
                            .into(),
                    )),
                    SignatureScheme::Secp256r1 => Ok(PublicKey::Secp256r1(
                        (&Secp256r1PublicKey::from_bytes(bytes).map_err(|_| {
                            SuiErrorKind::KeyConversionError(
                                "Cannot parse secp256r1 pk".to_string(),
                            )
                        })?)
                            .into(),
                    )),
                    _ => Err(SuiErrorKind::UnsupportedFeatureError {
                        error: "Unsupported signature scheme in MultiSig".to_string(),
                    }
                    .into()),
                }
            }
```

**File:** crates/sui-types/src/signature.rs (L230-230)
```rust
            GenericSignature::PasskeyAuthenticator(s) => s.get_pk(),
```

**File:** crates/sui-types/src/signature.rs (L246-270)
```rust
        match SignatureScheme::from_flag_byte(
            bytes.first().ok_or(FastCryptoError::InputTooShort(0))?,
        ) {
            Ok(x) => match x {
                SignatureScheme::ED25519
                | SignatureScheme::Secp256k1
                | SignatureScheme::Secp256r1 => Ok(GenericSignature::Signature(
                    Signature::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidSignature)?,
                )),
                SignatureScheme::MultiSig => match MultiSig::from_bytes(bytes) {
                    Ok(multisig) => Ok(GenericSignature::MultiSig(multisig)),
                    Err(_) => {
                        let multisig = MultiSigLegacy::from_bytes(bytes)?;
                        Ok(GenericSignature::MultiSigLegacy(multisig))
                    }
                },
                SignatureScheme::ZkLoginAuthenticator => {
                    let zk_login = ZkLoginAuthenticator::from_bytes(bytes)?;
                    Ok(GenericSignature::ZkLoginAuthenticator(zk_login))
                }
                SignatureScheme::PasskeyAuthenticator => {
                    let passkey = PasskeyAuthenticator::from_bytes(bytes)?;
                    Ok(GenericSignature::PasskeyAuthenticator(passkey))
                }
                _ => Err(FastCryptoError::InvalidInput),
```
