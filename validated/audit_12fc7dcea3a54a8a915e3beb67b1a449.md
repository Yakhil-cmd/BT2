[1](#0-0)

### Citations

**File:** crates/sui-core/src/consensus_adapter.rs (L46-52)
```rust
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::authority::consensus_tx_status_cache::{
    ConsensusTxStatus, NotifyReadConsensusTxStatusResult,
};
use crate::checkpoints::CheckpointStore;
use crate::consensus_handler::{SequencedConsensusTransactionKey, classify};
use crate::epoch::reconfiguration::{ReconfigState, ReconfigurationInitiator};
```
