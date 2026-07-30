[1](#0-0)

### Citations

**File:** crates/sui-core/src/execution_cache.rs (L1-46)
```rust
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::accumulators::funds_read::AccountFundsRead;
use crate::authority::AuthorityStore;
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::authority::authority_store::ExecutionLockWriteGuard;
#[cfg(test)]
use crate::authority::authority_store::SuiLockResult;
use crate::authority::backpressure::BackpressureManager;
use crate::authority::epoch_start_configuration::EpochFlag;
use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use crate::global_state_hasher::GlobalStateHashStore;
use crate::transaction_outputs::TransactionOutputs;
use either::Either;
use itertools::Itertools;
use mysten_common::ZipDebugEqIteratorExt;
use sui_types::accumulator_event::AccumulatorEvent;
use sui_types::bridge::Bridge;

use futures::{FutureExt, future::BoxFuture};
use prometheus::Registry;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use sui_config::ExecutionCacheConfig;
use sui_protocol_config::ProtocolVersion;
use sui_types::base_types::{FullObjectID, VerifiedExecutionData};
use sui_types::digests::{TransactionDigest, TransactionEffectsDigest};
use sui_types::effects::{TransactionEffects, TransactionEvents};
use sui_types::error::{SuiError, SuiErrorKind, SuiResult, UserInputError};
use sui_types::executable_transaction::VerifiedExecutableTransaction;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::object::Object;
use sui_types::storage::{
    BackingPackageStore, BackingStore, FullObjectKey, MarkerValue, ObjectKey, ObjectOrTombstone,
    ObjectStore, PackageObject, ParentSync, RuntimeObjectResolver,
};
use sui_types::sui_system_state::SuiSystemState;
use sui_types::transaction::VerifiedTransaction;
use sui_types::{
    base_types::{EpochId, ObjectID, ObjectRef, SequenceNumber},
    object::Owner,
    storage::InputKey,
};
use typed_store::rocks::DBBatch;
```
