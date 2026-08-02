[1](#0-0) [2](#0-1)

### Citations

**File:** types/src/aggregate_signature.rs (L81-87)
```rust
    /// Decompress the aggregated signature into a `bls12381::Signature`,
    /// performing the deferred G2-point decompression. Returns `Ok(None)` if no
    /// signature is present. This is the verification entry point — call it only
    /// after cheaper structural checks (bitmask, voting power) have passed.
    pub fn decompressed_sig(&self) -> Result<Option<bls12381::Signature>, CryptoMaterialError> {
        self.sig.as_ref().map(|s| s.decompress()).transpose()
    }
```

**File:** types/src/ledger_info.rs (L1-14)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

#[cfg(any(test, feature = "fuzzing"))]
use crate::validator_signer::ValidatorSigner;
use crate::{
    account_address::AccountAddress,
    block_info::{BlockInfo, Round},
    epoch_state::EpochState,
    lazy_bls::LazyBlsSignature,
    on_chain_config::ValidatorSet,
    transaction::Version,
    validator_verifier::{ValidatorVerifier, VerifyError},
};
```
