[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/spanned.rs (L14-18)
```rust
#[derive(Copy, Clone)]
pub struct Spanned<T> {
    pub idx: u16,
    pub value: T,
}
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/spanned.rs (L20-44)
```rust
impl<T: PartialEq> PartialEq for Spanned<T> {
    fn eq(&self, other: &Spanned<T>) -> bool {
        self.value == other.value
    }
}

impl<T: Eq> Eq for Spanned<T> {}

impl<T: Hash> Hash for Spanned<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl<T: PartialOrd> PartialOrd for Spanned<T> {
    fn partial_cmp(&self, other: &Spanned<T>) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<T: Ord> Ord for Spanned<T> {
    fn cmp(&self, other: &Spanned<T>) -> Ordering {
        self.value.cmp(&other.value)
    }
}
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/typing/verify/private_entry_arguments.rs (L417-442)
```rust
    sp!(_, c): &T::Command,
) -> Result<Vec<Option<Value>>, Mode::Error> {
    let T::Command_ {
        command,
        result_type,
        drop_values,
        incurs_post_execution_checks,
    } = c;
    let argument_cliques = arguments(env, context, command.arguments())?;
    match command {
        T::Command__::MoveCall(call) => move_call::<Mode>(env, context, call, &argument_cliques)?,
        T::Command__::TransferObjects(_, _)
        | T::Command__::SplitCoins(_, _, _)
        | T::Command__::MergeCoins(_, _, _)
        | T::Command__::MakeMoveVec(_, _)
        | T::Command__::Publish(_, _, _)
        | T::Command__::Upgrade(_, _, _, _, _) => (),
    }
    let merged_clique = context
        .cliques
        .merge::<Mode::Error>(argument_cliques.into_iter().map(|(_, c)| c).collect())?;
    if *incurs_post_execution_checks {
        context
            .cliques
            .mark_always_hot::<Mode::Error>(merged_clique)?;
    }
```
