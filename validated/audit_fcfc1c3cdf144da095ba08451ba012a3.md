[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/sui-types/src/storage/mod.rs (L60-78)
```rust
/// A potential input to a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InputKey {
    VersionedObject {
        id: FullObjectID,
        version: SequenceNumber,
    },
    Package {
        id: ObjectID,
    },
}

impl InputKey {
    pub fn id(&self) -> FullObjectID {
        match self {
            InputKey::VersionedObject { id, .. } => *id,
            InputKey::Package { id } => FullObjectID::Fastpath(*id),
        }
    }
```

**File:** crates/sui-types/src/storage/read_store.rs (L36-41)
```rust
pub trait ReadStore: ObjectStore {
    //
    // Committee Getters
    //

    fn get_committee(&self, epoch: EpochId) -> Option<Arc<Committee>>;
```

**File:** crates/sui-core/src/transaction_outputs.rs (L64-67)
```rust
        // Get the actual set of objects that have been received -- any received
        // object will show up in the modified-at set.
        let modified_at: HashSet<_> = effects.modified_at_versions().into_iter().collect();
        let possible_to_receive = transaction.transaction_data().receiving_objects();
```
