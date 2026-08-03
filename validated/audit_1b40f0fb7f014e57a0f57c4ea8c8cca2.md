[1](#0-0) [1](#0-0)

### Citations

**File:** storage/storage-interface/src/lib.rs (L377-379)
```rust
        /// Gets the latest LedgerView no matter if db has been bootstrapped.
        /// Used by the Db-bootstrapper.
        fn get_pre_committed_ledger_summary(&self) -> Result<LedgerSummary>;
```
