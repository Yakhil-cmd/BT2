[1](#0-0) [2](#0-1)

### Citations

**File:** api/src/transactions.rs (L23-30)
```rust
use aptos_api_types::{
    transaction::{PersistedAuxiliaryInfo, TransactionSummary},
    verify_function_identifier, verify_module_identifier, Address, AptosError, AptosErrorCode,
    AsConverter, EncodeSubmissionRequest, GasEstimation, GasEstimationBcs, HashValue,
    HexEncodedBytes, LedgerInfo, MoveType, PendingTransaction, SubmitTransactionRequest,
    Transaction, TransactionData, TransactionOnChainData, TransactionsBatchSingleSubmissionFailure,
    TransactionsBatchSubmissionResult, UserTransaction, VerifyInput, VerifyInputWithRecursion, U64,
};
```

**File:** api/src/transactions.rs (L121-133)
```rust
impl VerifyInput for SubmitTransactionsBatchPost {
    fn verify(&self) -> anyhow::Result<()> {
        match self {
            SubmitTransactionsBatchPost::Json(inner) => {
                for request in inner.0.iter() {
                    request.verify()?;
                }
            },
            SubmitTransactionsBatchPost::Bcs(_) => {},
        }
        Ok(())
    }
}
```
