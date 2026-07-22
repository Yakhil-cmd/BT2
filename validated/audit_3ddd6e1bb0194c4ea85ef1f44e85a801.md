The bug is real and confirmed by the code. Let me lay out the exact evidence.

---

### Title
Silent Drop of `AddMod`, `MulMod`, `RangeCheck96` Builtin Counts in P2P Receipt Serialization — (`crates/apollo_protobuf/src/converters/receipt.rs`)

### Summary

The `BuiltinCounter` protobuf message in `receipt.proto` has no fields for `AddMod`, `MulMod`, or `RangeCheck96`. The serialization (`From<HashMap<Builtin, u64>> for ProtobufBuiltinCounter`) silently discards those counts, and the deserialization (`TryFrom<ProtobufBuiltinCounter> for HashMap<Builtin, u64>`) never inserts them. Any transaction that uses these builtins will have its receipt's `builtin_instance_counter` corrupted on every node that syncs the block via P2P.

### Finding Description

**Protobuf schema gap (acknowledged with a TODO):**

The `BuiltinCounter` message in `receipt.proto` only defines 8 fields — `bitwise`, `ecdsa`, `ec_op`, `pedersen`, `range_check`, `poseidon`, `keccak`, `output` — with an explicit comment: [1](#0-0) 

**Serialization silently drops the three builtins:**

`From<HashMap<Builtin, u64>> for ProtobufBuiltinCounter` only writes the 7 supported builtins and hardcodes `output: 0`. There is no write for `Builtin::AddMod`, `Builtin::MulMod`, or `Builtin::RangeCheck96`: [2](#0-1) 

**Deserialization never inserts them:**

`TryFrom<ProtobufBuiltinCounter> for HashMap<Builtin, u64>` inserts only 7 builtins (plus `SegmentArena: 0`). `AddMod`, `MulMod`, and `RangeCheck96` are absent: [3](#0-2) 

**The `Builtin` enum does define all three:** [4](#0-3) 

**The `ExecutionResources` struct uses `builtin_instance_counter` as a `HashMap<Builtin, u64>`:** [5](#0-4) 

### Impact Explanation

Any node syncing blocks via P2P will deserialize receipts with `builtin_instance_counter` entries for `AddMod`, `MulMod`, and `RangeCheck96` silently zeroed/absent. This corrupts the stored `ExecutionResources` for every affected transaction. When those receipts are served via RPC (e.g., `starknet_getTransactionReceipt`), the returned `execution_resources.builtin_instance_counter` will be wrong — missing counts that were actually consumed. This is a **High** impact: RPC returns an authoritative-looking wrong value.

The bouncer claim in the question is **incorrect**: the bouncer runs on the sequencer during block production using live blockifier output, not P2P-synced receipts. So the "incorrect gas accounting for bouncer" angle does not apply.

### Likelihood Explanation

`AddMod`, `MulMod`, and `RangeCheck96` are used by Cairo programs that perform modular arithmetic (e.g., ECDSA verification helpers, range-checked arithmetic). Any unprivileged user submitting such a transaction triggers the corruption on all syncing peers. No special privileges required.

### Recommendation

1. Add `add_mod`, `mul_mod`, and `range_check96` fields to the `BuiltinCounter` protobuf message in `receipt.proto`.
2. Update `From<HashMap<Builtin, u64>> for ProtobufBuiltinCounter` to write those three fields.
3. Update `TryFrom<ProtobufBuiltinCounter> for HashMap<Builtin, u64>` to read and insert those three fields.
4. Remove the `// TODO(alonl): add the missing builtins` comment once done.

### Proof of Concept

```rust
use std::collections::HashMap;
use starknet_api::execution_resources::{Builtin, ExecutionResources};
// (using the From/TryFrom impls in apollo_protobuf/src/converters/receipt.rs)

let mut resources = ExecutionResources::default();
resources.builtin_instance_counter.insert(Builtin::AddMod, 42);

// Serialize to protobuf
let proto: protobuf::receipt::ExecutionResources = resources.into();

// Deserialize back
let restored = ExecutionResources::try_from(proto).unwrap();

// AddMod count is gone
assert_eq!(restored.builtin_instance_counter.get(&Builtin::AddMod), None);
// Same for MulMod and RangeCheck96
```

### Citations

**File:** crates/apollo_protobuf/src/proto/p2p/proto/sync/receipt.proto (L21-31)
```text
    message BuiltinCounter {
      uint32 bitwise = 1;
      uint32 ecdsa = 2;
      uint32 ec_op = 3;
      uint32 pedersen = 4;
      uint32 range_check = 5;
      uint32 poseidon = 6;
      uint32 keccak = 7;
      uint32 output = 8;
      // TODO(alonl): add the missing builtins
    }
```

**File:** crates/apollo_protobuf/src/converters/receipt.rs (L253-267)
```rust
impl TryFrom<ProtobufBuiltinCounter> for HashMap<Builtin, u64> {
    type Error = ProtobufConversionError;
    fn try_from(value: ProtobufBuiltinCounter) -> Result<Self, Self::Error> {
        let mut builtin_instance_counter = HashMap::new();
        builtin_instance_counter.insert(Builtin::RangeCheck, u64::from(value.range_check));
        builtin_instance_counter.insert(Builtin::Pedersen, u64::from(value.pedersen));
        builtin_instance_counter.insert(Builtin::Poseidon, u64::from(value.poseidon));
        builtin_instance_counter.insert(Builtin::EcOp, u64::from(value.ec_op));
        builtin_instance_counter.insert(Builtin::Ecdsa, u64::from(value.ecdsa));
        builtin_instance_counter.insert(Builtin::Bitwise, u64::from(value.bitwise));
        builtin_instance_counter.insert(Builtin::Keccak, u64::from(value.keccak));
        builtin_instance_counter.insert(Builtin::SegmentArena, 0);
        Ok(builtin_instance_counter)
    }
}
```

**File:** crates/apollo_protobuf/src/converters/receipt.rs (L269-291)
```rust
impl From<HashMap<Builtin, u64>> for ProtobufBuiltinCounter {
    fn from(value: HashMap<Builtin, u64>) -> Self {
        let builtin_counter = ProtobufBuiltinCounter {
            range_check: u32::try_from(*value.get(&Builtin::RangeCheck).unwrap_or(&0))
                // TODO(Shahak): should not panic
                .expect("Failed to convert u64 to u32"),
            pedersen: u32::try_from(*value.get(&Builtin::Pedersen).unwrap_or(&0))
                .expect("Failed to convert u64 to u32"),
            poseidon: u32::try_from(*value.get(&Builtin::Poseidon).unwrap_or(&0))
                .expect("Failed to convert u64 to u32"),
            ec_op: u32::try_from(*value.get(&Builtin::EcOp).unwrap_or(&0))
                .expect("Failed to convert u64 to u32"),
            ecdsa: u32::try_from(*value.get(&Builtin::Ecdsa).unwrap_or(&0))
                .expect("Failed to convert u64 to u32"),
            bitwise: u32::try_from(*value.get(&Builtin::Bitwise).unwrap_or(&0))
                .expect("Failed to convert u64 to u32"),
            keccak: u32::try_from(*value.get(&Builtin::Keccak).unwrap_or(&0))
                .expect("Failed to convert u64 to u32"),
            output: 0,
        };
        builtin_counter
    }
}
```

**File:** crates/starknet_api/src/execution_resources.rs (L230-237)
```rust
#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
pub struct ExecutionResources {
    pub steps: u64,
    pub builtin_instance_counter: HashMap<Builtin, u64>,
    pub memory_holes: u64,
    pub da_gas_consumed: GasVector,
    pub gas_consumed: GasVector,
}
```

**File:** crates/starknet_api/src/execution_resources.rs (L239-263)
```rust
#[derive(Clone, Debug, Deserialize, EnumIter, Eq, Hash, PartialEq, Serialize)]
pub enum Builtin {
    #[serde(rename = "range_check_builtin_applications")]
    RangeCheck,
    #[serde(rename = "pedersen_builtin_applications")]
    Pedersen,
    #[serde(rename = "poseidon_builtin_applications")]
    Poseidon,
    #[serde(rename = "ec_op_builtin_applications")]
    EcOp,
    #[serde(rename = "ecdsa_builtin_applications")]
    Ecdsa,
    #[serde(rename = "bitwise_builtin_applications")]
    Bitwise,
    #[serde(rename = "keccak_builtin_applications")]
    Keccak,
    #[serde(rename = "segment_arena_builtin")]
    SegmentArena,
    #[serde(rename = "add_mod_builtin")]
    AddMod,
    #[serde(rename = "mul_mod_builtin")]
    MulMod,
    #[serde(rename = "range_check96_builtin")]
    RangeCheck96,
}
```
