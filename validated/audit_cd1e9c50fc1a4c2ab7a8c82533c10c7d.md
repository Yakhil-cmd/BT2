[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** types/src/transaction/authenticator.rs (L32-41)
```rust
/// Maximum number of signatures supported in `TransactionAuthenticator`,
/// across all `AccountAuthenticator`s included.
pub const MAX_NUM_OF_SIGS: usize = 32;

/// An error enum for issues related to transaction or account authentication.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{:?}", self)]
pub enum AuthenticationError {
    /// The number of signatures exceeds the maximum supported.
    MaxSignaturesExceeded,
```

**File:** types/src/transaction/authenticator.rs (L86-98)
```rust
    MultiAgent {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
    },
    /// Optional Multi-agent transaction with a fee payer.
    FeePayer {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
        fee_payer_address: AccountAddress,
        fee_payer_signer: AccountAuthenticator,
    },
```
