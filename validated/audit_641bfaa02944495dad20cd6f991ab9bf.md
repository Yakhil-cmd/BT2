[1](#0-0)

### Citations

**File:** sui-execution/latest/sui-adapter/src/execution_engine.rs (L1-50)
```rust
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub use checked::*;

#[sui_macros::with_checked_arithmetic]
mod checked {

    use crate::adapter::new_move_runtime;
    use crate::execution_mode::{self, ExecutionMode};
    use crate::execution_value::SuiResolver;
    use crate::gas_charger::{PaymentKind, PaymentMethod};
    use move_binary_format::CompiledModule;
    use move_trace_format::format::MoveTraceBuilder;
    use move_vm_runtime::runtime::MoveRuntime;
    use mysten_common::{assert_reachable, debug_fatal, in_test_configuration};
    use std::collections::{BTreeMap, BTreeSet};
    use std::{cell::RefCell, collections::HashSet, rc::Rc, sync::Arc};
    use sui_types::accumulator_root::{ACCUMULATOR_ROOT_CREATE_FUNC, ACCUMULATOR_ROOT_MODULE};
    use sui_types::balance::{
        BALANCE_CREATE_REWARDS_FUNCTION_NAME, BALANCE_DESTROY_REBATES_FUNCTION_NAME,
        BALANCE_MODULE_NAME,
    };
    use sui_types::coin_reservation::ParsedDigest;
    use sui_types::execution_params::ExecutionOrEarlyError;
    use sui_types::gas_coin::GAS;
    use sui_types::messages_checkpoint::CheckpointTimestamp;
    use sui_types::metrics::ExecutionMetrics;
    use sui_types::object::OBJECT_START_VERSION;
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::randomness_state::{
        RANDOMNESS_MODULE_NAME, RANDOMNESS_STATE_CREATE_FUNCTION_NAME,
        RANDOMNESS_STATE_UPDATE_FUNCTION_NAME,
    };
    use sui_types::{BRIDGE_ADDRESS, SUI_BRIDGE_OBJECT_ID, SUI_RANDOMNESS_STATE_OBJECT_ID};
    use tracing::{info, instrument, trace, warn};

    use crate::static_programmable_transactions as SPT;
    use crate::sui_types::gas::SuiGasStatusAPI;
    use crate::{gas_charger::GasCharger, temporary_store::TemporaryStore};
    use move_core_types::ident_str;
    use move_core_types::language_storage::TypeTag;
    use sui_move_natives::all_natives;
    use sui_protocol_config::{
        Chain, LimitThresholdCrossed, PerObjectCongestionControlMode, ProtocolConfig,
        check_limit_by_meter,
    };
    use sui_types::authenticator_state::{
        AUTHENTICATOR_STATE_CREATE_FUNCTION_NAME, AUTHENTICATOR_STATE_EXPIRE_JWKS_FUNCTION_NAME,
        AUTHENTICATOR_STATE_MODULE_NAME, AUTHENTICATOR_STATE_UPDATE_FUNCTION_NAME,
```
