[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-core/src/checkpoints/checkpoint_executor/mod.rs (L1-1)
```rust
// Copyright (c) Mysten Labs, Inc.
```

**File:** crates/sui-core/src/epoch/randomness.rs (L1-44)
```rust
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anemo::PeerId;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use fastcrypto_tbls::{dkg_v1, dkg_v1::Output, nodes, nodes::PartyId};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use mysten_common::debug_fatal;
use parking_lot::Mutex;
use rand::SeedableRng;
use rand::rngs::{OsRng, StdRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};
use std::time::Instant;
use sui_macros::fail_point_if;
use sui_network::randomness;
use sui_types::base_types::AuthorityName;
use sui_types::committee::{Committee, EpochId, StakeUnit};
use sui_types::crypto::{AuthorityKeyPair, RandomnessRound};
use sui_types::error::{SuiErrorKind, SuiResult};
use sui_types::messages_consensus::{
    ConsensusTransaction, Round, TimestampMs, VersionedDkgConfirmation, VersionedDkgMessage,
};
use sui_types::sui_system_state::epoch_start_sui_system_state::EpochStartSystemStateTrait;
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use typed_store::Map;

use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, consensus_quarantine::ConsensusCommitOutput,
};
use crate::authority::epoch_start_configuration::EpochStartConfigTrait;
use crate::consensus_adapter::SubmitToConsensus;
use crate::randomness_round_receiver::RandomnessRoundReceiverHandle;

type PkG = bls12381::G2Element;
type EncG = bls12381::G2Element;
```
