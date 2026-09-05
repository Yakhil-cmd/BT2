[1](#0-0) [2](#0-1)

### Citations

**File:** stackslib/src/chainstate/burn/operations/mod.rs (L1-45)
```rust
// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{error, fmt};

use clarity::vm::types::PrincipalData;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, VRFSeed,
};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{hex_bytes, to_hex};
use stacks_common::util::vrf::VRFPublicKey;

use self::leader_block_commit::Treatment;
use crate::burnchains::{BurnchainSigner, Txid};
use crate::chainstate::burn::operations::leader_block_commit::MissedBlockCommit;
use crate::chainstate::burn::{ConsensusHash, Opcodes};
use crate::chainstate::stacks::address::PoxAddress;
use crate::util_lib::db::Error as db_error;

pub mod delegate_stx;
pub mod leader_block_commit;
pub mod leader_key_register;
pub mod stack_stx;
pub mod transfer_stx;
pub mod vote_for_aggregate_key;

#[cfg(test)]
mod test;
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1-1)
```text
(define-constant ERR_UNAUTHORIZED (err u1))
```
