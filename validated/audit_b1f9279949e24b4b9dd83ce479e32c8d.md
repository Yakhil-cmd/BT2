[1](#0-0) [2](#0-1)

### Citations

**File:** types/src/transaction/authenticator.rs (L1-30)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    account_address::AccountAddress,
    function_info::FunctionInfo,
    keyless::{
        EphemeralCertificate, FederatedKeylessPublicKey, KeylessPublicKey, KeylessSignature,
        TransactionAndProof,
    },
    transaction::{
        webauthn::PartialAuthenticatorAssertionResponse, RawTransaction, RawTransactionWithData,
    },
};
use anyhow::{bail, ensure, Error, Result};
use aptos_crypto::{
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    hash::CryptoHash,
    multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature},
    secp256k1_ecdsa, secp256r1_ecdsa, signing_message, slh_dsa_sha2_128s,
    traits::Signature,
    CryptoMaterialError, HashValue, ValidCryptoMaterial, ValidCryptoMaterialStringExt,
};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher, DeserializeKey, SerializeKey};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{convert::TryFrom, fmt, str::FromStr};
use thiserror::Error;
```
