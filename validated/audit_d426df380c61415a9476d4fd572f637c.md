[1](#0-0) [2](#0-1)

### Citations

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L27-30)
```rust
    pub fee_payer: Option<AccountAddress>,
    /// `None` if the [TransactionAuthenticator] lacks an authenticator for the fee payer.
    /// `Some([])` if the authenticator for the fee payer is a [NoAccountAuthenticator].
    pub fee_payer_authentication_proof: Option<AuthenticationProof>,
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L142-146)
```rust
            fee_payer: txn.authenticator_ref().fee_payer_address(),
            fee_payer_authentication_proof: txn
                .authenticator()
                .fee_payer_signer()
                .map(|signer| signer.authentication_proof()),
```
