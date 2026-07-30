[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-config/src/certificate_deny_config.rs (L1-20)
```rust
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use sui_types::base_types::TransactionDigest;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CertificateDenyConfig {
    /// A list of certificate digests that are known to be either deterministically crashing
    /// every validator, or causing every validator to hang forever, i.e. there is no way
    /// for such transaction to execute successfully today.
    /// Now with this config, a validator will decide that this transaction will always yield
    /// ExecutionError and charge gas accordingly.
    /// This config is meant for a fast temporary fix for a known issue, and should be removed
    /// once the issue is fixed. However, since a certificate once executed will be included
    /// in checkpoints, all future executions of this transaction through replay must also lead
    /// to the same result (i.e. ExecutionError). So when we remove this config, we need to make
```

**File:** crates/sui-core/src/authority.rs (L1-1)
```rust
// Copyright (c) 2021, Facebook, Inc. and its affiliates
```
