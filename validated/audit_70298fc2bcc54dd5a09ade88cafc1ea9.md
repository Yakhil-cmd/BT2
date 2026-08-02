[1](#0-0)

### Citations

**File:** types/src/proof/definition.rs (L1-14)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! This module has definition of various proofs.

use super::{
    accumulator::InMemoryAccumulator, position::Position, verify_transaction_info,
    MerkleTreeInternalNode, SparseMerkleInternalNode, SparseMerkleLeafNode,
};
use crate::{
    ledger_info::LedgerInfo,
    proof::accumulator::InMemoryTransactionAccumulator,
    transaction::{TransactionInfo, Version},
};
```
