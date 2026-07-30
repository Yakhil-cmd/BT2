[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-types/src/effects/effects_v2.rs (L604-621)
```rust
                SharedInput::ConsensusStreamEnded((id, version, mutability, _)) => {
                    debug_assert!(!changed_objects.contains_key(&id));
                    match mutability {
                        SharedObjectMutability::Mutable => Some((
                            id,
                            UnchangedConsensusKind::MutateConsensusStreamEnded(version),
                        )),
                        SharedObjectMutability::Immutable => Some((
                            id,
                            UnchangedConsensusKind::ReadConsensusStreamEnded(version),
                        )),
                        // This is current unreachable, because non exclusive writes are not exposed to
                        // user transactions yet, and so there is no way for their inputs to be deleted.
                        SharedObjectMutability::NonExclusiveWrite => Some((
                            id,
                            UnchangedConsensusKind::MutateConsensusStreamEnded(version),
                        )),
                    }
```
