[1](#0-0)

### Citations

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/loading/ast.rs (L124-139)
```rust
#[derive(Debug)]
pub enum Command {
    MoveCall(Box<MoveCall>),
    TransferObjects(Vec<Argument>, Argument),
    SplitCoins(Argument, Vec<Argument>),
    MergeCoins(Argument, Vec<Argument>),
    MakeMoveVec(/* T for vector<T> */ Option<Type>, Vec<Argument>),
    Publish(PackagePayload, Vec<ObjectID>, ResolvedLinkage),
    Upgrade(
        PackagePayload,
        Vec<ObjectID>,
        ObjectID,
        Argument,
        ResolvedLinkage,
    ),
}
```
