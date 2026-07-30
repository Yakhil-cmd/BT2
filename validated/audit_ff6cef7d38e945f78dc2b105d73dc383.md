[1](#0-0)

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/registries/coin_registry.move (L1-20)
```text
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Defines the system object for managing coin data in a central
/// registry. This module provides a centralized way to store and manage
/// metadata for all currencies in the Sui ecosystem, including their
/// supply information, regulatory status, and metadata capabilities.
module sui::coin_registry;

use std::ascii;
use std::string::String;
use std::type_name::{Self, TypeName};
use sui::bag::{Self, Bag};
use sui::balance::{Supply, Balance};
use sui::coin::{Self, TreasuryCap, DenyCapV2, CoinMetadata, RegulatedCoinMetadata, Coin};
use sui::derived_object;
use sui::dynamic_field as df;
use sui::transfer::Receiving;
use sui::vec_map::{Self, VecMap};

```
