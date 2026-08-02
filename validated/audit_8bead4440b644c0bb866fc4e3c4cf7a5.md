[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** third_party/move/move-core/types/src/effects.rs (L71-124)
```rust
/// A collection of resource operations on a Move account.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AccountChanges<Resource> {
    resources: BTreeMap<StructTag, Op<Resource>>,
}

/// This implements an algorithm to squash two change sets together by merging pairs of operations
/// on the same item together. This is similar to squashing two commits in a version control system.
///
/// It should be noted that all operation types have some implied pre and post conditions:
///   - New
///     - before: data doesn't exist
///     - after: data exists (new)
///   - Modify
///     - before: data exists
///     - after: data exists (modified)
///   - Delete
///     - before: data exists
///     - after: data does not exist (deleted)
///
/// It is possible to have a pair of operations resulting in conflicting states, in which case the
/// squash will fail.
fn squash<K, V>(map: &mut BTreeMap<K, Op<V>>, other: BTreeMap<K, Op<V>>) -> Result<()>
where
    K: Ord,
{
    use btree_map::Entry::*;
    use Op::*;

    for (key, op) in other.into_iter() {
        match map.entry(key) {
            Occupied(mut entry) => {
                let r = entry.get_mut();
                match (r.as_ref(), op) {
                    (Modify(_) | New(_), New(_)) | (Delete, Delete | Modify(_)) => {
                        bail!("The given change sets cannot be squashed")
                    },
                    (Modify(_), Modify(data)) => *r = Modify(data),
                    (New(_), Modify(data)) => *r = New(data),
                    (Modify(_), Delete) => *r = Delete,
                    (Delete, New(data)) => *r = Modify(data),
                    (New(_), Delete) => {
                        entry.remove();
                    },
                }
            },
            Vacant(entry) => {
                entry.insert(op);
            },
        }
    }

    Ok(())
}
```

**File:** third_party/move/move-core/types/src/effects.rs (L259-263)
```rust
// These aliases are necessary because AccountChangeSet and ChangeSet were not
// generic before. In order to minimise the code changes we alias new generic
// types.
pub type AccountChangeSet = AccountChanges<Bytes>;
pub type ChangeSet = Changes<Bytes>;
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L41-42)
```rust
use move_core_types::{
    effects::{AccountChanges, Changes, Op as MoveStorageOp},
```
