[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/typing/translate.rs (L91-111)
```rust
        for (i, (arg, ty)) in linputs.into_iter().enumerate() {
            let idx = T::InputIndex(checked_as!(i, u16)?);
            let kind = match (arg, ty) {
                (L::InputArg::Pure(bytes), L::InputType::Bytes) => {
                    let (byte_index, _) = context.bytes.insert_full(bytes);
                    context.bytes_idx_remapping.insert(idx, byte_index);
                    InputKind::Pure
                }
                (L::InputArg::Receiving(oref), L::InputType::Bytes) => {
                    context.receiving_refs.insert(idx, oref);
                    InputKind::Receiving
                }
                (L::InputArg::Object(arg), L::InputType::Fixed(ty)) => {
                    let o = T::ObjectInput {
                        original_input_index: idx,
                        arg,
                        ty,
                    };
                    context.objects.insert(idx, o);
                    InputKind::Object
                }
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/typing/verify/input_arguments.rs (L304-328)
```rust
fn check_obj_by_mut_ref<E: ExecutionErrorTrait>(
    context: &mut Context,
    arg_idx: u16,
    location: &T::Location,
) -> Result<(), E> {
    match location {
        T::Location::WithdrawalInput(_)
        | T::Location::PureInput(_)
        | T::Location::ReceivingInput(_)
        | T::Location::TxContext
        | T::Location::GasCoin
        | T::Location::Result(_, _) => Ok(()),
        T::Location::ObjectInput(idx) => {
            if !context.objects.safe_get(*idx as usize)?.allow_by_mut_ref {
                Err(command_argument_error(
                    CommandArgumentError::InvalidObjectByMutRef,
                    arg_idx as usize,
                )
                .into())
            } else {
                Ok(())
            }
        }
    }
}
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/typing/verify/drop_safety.rs (L234-261)
```rust
        fn new<Mode: ExecutionMode>(_env: &Env<Mode>, ast: &T::Transaction) -> Self {
            let objects = ast.objects.iter().map(|_| Some(Value)).collect::<Vec<_>>();
            let withdrawals = ast
                .withdrawals
                .iter()
                .map(|_| Some(Value))
                .collect::<Vec<_>>();
            let pure = ast.pure.iter().map(|_| Some(Value)).collect::<Vec<_>>();
            let receiving = ast
                .receiving
                .iter()
                .map(|_| Some(Value))
                .collect::<Vec<_>>();
            let gas_coin = if ast.gas_payment.is_none() {
                None
            } else {
                Some(Value)
            };
            Self {
                tx_context: Some(Value),
                gas_coin,
                objects,
                withdrawals,
                pure,
                receiving,
                results: Vec::with_capacity(ast.commands.len()),
            }
        }
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/typing/verify/memory_safety.rs (L72-97)
```rust
impl Context {
    fn new<Mode: ExecutionMode>(
        _env: &Env<Mode>,
        ast: &T::Transaction,
    ) -> Result<Self, Mode::Error> {
        let gas_coin = if ast.gas_payment.is_none() {
            None
        } else {
            Some(Value::NonRef)
        };
        let objects = ast.objects.iter().map(|_| Some(Value::NonRef)).collect();
        let withdrawals = ast
            .withdrawals
            .iter()
            .map(|_| Some(Value::NonRef))
            .collect::<Vec<_>>();
        let pure = ast
            .pure
            .iter()
            .map(|_| Some(Value::NonRef))
            .collect::<Vec<_>>();
        let receiving = ast
            .receiving
            .iter()
            .map(|_| Some(Value::NonRef))
            .collect::<Vec<_>>();
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/execution/context.rs (L1506-1516)
```rust
        let arg = match location {
            T::Location::TxContext => return Ok(None),
            T::Location::GasCoin => TxArgument::GasCoin,
            T::Location::Result(i, j) => TxArgument::NestedResult(i, j),
            T::Location::ObjectInput(i) => TxArgument::Input(
                self.locations
                    .input_object_metadata
                    .safe_get(i as usize)?
                    .0
                    .0,
            ),
```
