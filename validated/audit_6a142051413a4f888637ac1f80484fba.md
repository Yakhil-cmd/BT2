[1](#0-0)

### Citations

**File:** crates/sui-core/src/authority/authority_store_pruner.rs (L34-44)
```rust
use sui_types::committee::EpochId;
use sui_types::effects::TransactionEffects;
use sui_types::effects::TransactionEffectsAPI;
use sui_types::message_envelope::Message;
use sui_types::messages_checkpoint::{
    CheckpointContents, CheckpointDigest, CheckpointSequenceNumber,
};
use sui_types::{
    base_types::{ObjectID, SequenceNumber, TransactionDigest},
    storage::ObjectKey,
};
```
