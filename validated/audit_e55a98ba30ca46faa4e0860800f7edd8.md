[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** types/src/transaction/multisig.rs (L41-51)
```rust
    pub fn as_transaction_executable(&self) -> TransactionExecutable {
        match &self.transaction_payload {
            Some(MultisigTransactionPayload::EntryFunction(entry)) => {
                TransactionExecutable::EntryFunction(entry.clone())
            },
            Some(MultisigTransactionPayload::Script(script)) => {
                TransactionExecutable::Script(script.clone())
            },
            None => TransactionExecutable::Empty,
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L21-26)
```text
/// 3. To create a new transaction, an owner can call create_transaction with the transaction payload. This will store
/// the full transaction payload on chain, which adds decentralization (censorship is not possible as the data is
/// available on chain) and makes it easier to fetch all transactions waiting for execution. If saving gas is desired,
/// an owner can alternatively call create_transaction_with_hash where only the payload hash is stored. Later execution
/// will be verified using the hash. Only owners can create transactions and a transaction id (incremeting id) will be
/// assigned.
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L62-68)
```text
    // Any error codes > 2000 can be thrown as part of transaction prologue.
    /// Owner list cannot contain the same address more than once.
    const EDUPLICATE_OWNER: u64 = 1;
    /// Specified account is not a multisig account.
    const EACCOUNT_NOT_MULTISIG: u64 = 2002;
    /// Account executing this operation is not an owner of the multisig account.
    const ENOT_OWNER: u64 = 2003;
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L69-80)
```text
    /// Transaction payload cannot be empty.
    const EPAYLOAD_CANNOT_BE_EMPTY: u64 = 4;
    /// Multisig account must have at least one owner.
    const ENOT_ENOUGH_OWNERS: u64 = 5;
    /// Transaction with specified id cannot be found.
    const ETRANSACTION_NOT_FOUND: u64 = 2006;
    /// Provided target function does not match the hash stored in the on-chain transaction.
    const EPAYLOAD_DOES_NOT_MATCH_HASH: u64 = 2008;
    /// Transaction has not received enough approvals to be executed.
    const ENOT_ENOUGH_APPROVALS: u64 = 2009;
    /// Provided target function does not match the payload stored in the on-chain transaction.
    const EPAYLOAD_DOES_NOT_MATCH: u64 = 2010;
```
