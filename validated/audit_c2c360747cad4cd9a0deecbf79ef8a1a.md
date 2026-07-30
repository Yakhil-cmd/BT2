[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-core/src/signature_verifier.rs (L19-31)
```rust
use sui_types::signature_verification::{
    VerifiedDigestCache, verify_sender_signed_data_message_signatures,
};
use sui_types::storage::ObjectStore;
use sui_types::transaction::{SenderSignedData, TransactionDataAPI};
use sui_types::{
    committee::Committee,
    crypto::{AuthoritySignInfoTrait, VerificationObligation},
    error::{SuiErrorKind, SuiResult},
    message_envelope::Message,
    messages_checkpoint::SignedCheckpointSummary,
    signature::VerifyParams,
};
```

**File:** crates/sui-core/src/signature_verifier.rs (L34-36)
```rust
/// Verifies signatures in ways that are faster than verifying each signature individually.
/// - BLS signatures (checkpoints) - batch verification.
/// - User signed data - caching.
```
