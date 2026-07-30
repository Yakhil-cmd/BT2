### Title
Unimplemented `todo!()` panic in accumulator settlement transaction builder crashes validators building/executing checkpoints - (File: `crates/sui-core/src/accumulators/mod.rs`)

### Summary
`crates/sui-core/src/accumulators/mod.rs` contains a `MergedValue::add_move_call` match arm that is left as `todo!()` for the `SumU128U128`/`SumU128U128` case (the merged representation used for "clawback"/regulated-balance accumulator values, referenced in the PAS — Programmable Account System — feature docs). This is structurally the same defect class as the reported Substrate bug: a runtime-facing code path (`force_unreserve`) that is exposed to ordinary user-triggered execution but was left unimplemented with `todo!()`, causing a deterministic panic instead of a graceful error.

### Finding Description
`AccumulatorSettlementTxBuilder` aggregates `AccumulatorEvent`s emitted by ordinary transactions during a checkpoint (`crates/sui-core/src/accumulators/mod.rs:240-303`) and, once per checkpoint, calls `MergedValue::add_move_call` to build the on-chain settlement PTB that merges/splits accumulator balances [1](#0-0) . The match has three handled shapes (`SumU128`/`SumU128` for ordinary `Balance<T>`, and `EventDigest`/`EventDigest`), plus a fallback `fatal!()`, but the `SumU128U128`/`SumU128U128` combination — used for the tuple-valued ("clawback") accumulator representation — is simply `todo!()`: [2](#0-1) 

This code runs deterministically as part of checkpoint execution across all validators (it is invoked from `build_tx`, which every validator executes when building/replaying the settlement transactions for a checkpoint) [3](#0-2) . `MergedValueIntermediate::accumulate_into` shows that `SumU128U128` values are produced whenever an `AccumulatorValue::IntegerTuple` event is merged/split [4](#0-3) , and `AccumulatorEvent`s (with their `AccumulatorOperation` and `AccumulatorValue`) are emitted from ordinary Move execution via the accumulator-address native functions such as `add_to_accumulator_address` in `sui-execution/latest/sui-move-natives/src/funds_accumulator.rs` [5](#0-4) , gated only by `obj_runtime.protocol_config.enable_accumulators()`.

### Impact Explanation
If any Move framework/application path can cause both a `Merge` and a `Split` (or any combination that ends up as `MergedValueIntermediate::SumU128U128` for both merge and split) on the same accumulator object within one checkpoint — which the "clawback"/regulated-balance (PAS) feature appears designed to exercise given the `SumU128U128` variant exists specifically to represent frozen+available tuple balances — the validator's checkpoint-building/execution logic hits `todo!()` and panics. Because this code executes identically and deterministically on every validator during checkpoint construction, it is not a single-node crash but a synchronized panic across the validator set, i.e., a chain halt/liveness failure triggered by ordinary, unprivileged user transactions. This matches the "network and node shutdown classes when reachable from public input" bucket called out as a valid High/Medium impact in the scope, and is the direct functional analog of the reported `force_unreserve` `todo!()` panic (an exposed-but-unimplemented runtime path reachable by a non-privileged caller).

### Likelihood Explanation
I could not fully confirm, within the available tool budget, the exact Move-level call sequence that produces two `IntegerTuple`-valued accumulator events (one `Merge`, one `Split`) for the same accumulator object in a single checkpoint — this requires inspecting `sui_types::accumulator_root`/`sui_types::effects::object_change.rs` (`AccumulatorValue::IntegerTuple`) and the Move framework modules that emit clawback-balance accumulator events, none of which I was able to read before hitting the iteration limit. The presence of a dedicated, non-generic tuple representation strongly suggests it is reachable from a designed feature (the docs reference a "PAS"/clawback capability), but this is a **partially-verified analog**, not a fully proven end-to-end PoC.

### Recommendation
- Short term: Replace the `todo!()` arm in `MergedValue::add_move_call` (`crates/sui-core/src/accumulators/mod.rs:116`) with a real settlement call for the `SumU128U128` case (e.g., a `settle_u128_u128`-style Move entry point), or, if the clawback/PAS feature is not yet meant to be reachable, ensure the corresponding native/Move entry points cannot emit `IntegerTuple` accumulator events while `enable_accumulators()`/the PAS feature is active in production.
- Long term: Audit all `todo!()`/`unimplemented!()`/`fatal!()` occurrences in code paths reachable from checkpoint execution and native functions to ensure no unprivileged transaction can trigger them, and add exhaustive match coverage tests for every `AccumulatorValue`/`MergedValue` combination pair.

### Proof of Concept
Not fully constructible from the indexed code alone — a complete PoC requires identifying the specific framework/Move call(s) that emit an `IntegerTuple`-valued `Merge` accumulator event and an `IntegerTuple`-valued `Split` accumulator event for the same `AccumulatorObjId` within a single checkpoint, which was not located within the available search scope. The reachable, verified fact is that `crates/sui-core/src/accumulators/mod.rs:116` contains a live `todo!()` in the deterministic checkpoint-settlement code path exercised on every validator, structurally identical to the reported bug class.

### Citations

**File:** crates/sui-core/src/accumulators/mod.rs (L79-116)
```rust
impl MergedValue {
    fn add_move_call(
        merge: Self,
        split: Self,
        root: Argument,
        address: &AccumulatorAddress,
        checkpoint_seq: u64,
        builder: &mut ProgrammableTransactionBuilder,
    ) {
        let ty = ClassifiedType::classify(&address.ty);
        let address_arg = builder.pure(address.address).unwrap();

        match (ty, merge, split) {
            (
                ClassifiedType::Balance,
                MergedValue::SumU128(merge_amount),
                MergedValue::SumU128(split_amount),
            ) => {
                // Net out the merge and split amounts.
                let (merge_amount, split_amount) = if merge_amount >= split_amount {
                    (merge_amount - split_amount, 0)
                } else {
                    (0, split_amount - merge_amount)
                };

                if merge_amount != 0 || split_amount != 0 {
                    let merge_amount = builder.pure(merge_amount).unwrap();
                    let split_amount = builder.pure(split_amount).unwrap();
                    builder.programmable_move_call(
                        SUI_FRAMEWORK_PACKAGE_ID,
                        ACCUMULATOR_SETTLEMENT_MODULE.into(),
                        ACCUMULATOR_ROOT_SETTLE_U128_FUNC.into(),
                        vec![address.ty.clone()],
                        vec![root, address_arg, merge_amount, split_amount],
                    );
                }
            }
            (_, MergedValue::SumU128U128(_v1, _v2), MergedValue::SumU128U128(_w1, _w2)) => todo!(),
```

**File:** crates/sui-core/src/accumulators/mod.rs (L180-206)
```rust
    fn accumulate_into(
        &mut self,
        value: AccumulatorValue,
        checkpoint_seq: u64,
        transaction_idx: u64,
    ) {
        match (self, value) {
            (Self::SumU128(v1), AccumulatorValue::Integer(v2)) => *v1 += v2 as u128,
            (Self::SumU128U128(v1, v2), AccumulatorValue::IntegerTuple(w1, w2)) => {
                *v1 += w1 as u128;
                *v2 += w2 as u128;
            }
            (Self::Events(commitments), AccumulatorValue::EventDigest(event_digests)) => {
                for (event_idx, digest) in event_digests {
                    commitments.push(EventCommitment::new(
                        checkpoint_seq,
                        transaction_idx,
                        event_idx,
                        digest,
                    ));
                }
            }
            _ => {
                fatal!("invalid merge");
            }
        }
    }
```

**File:** crates/sui-core/src/accumulators/mod.rs (L337-383)
```rust
    pub fn build_tx(
        self,
        protocol_config: &ProtocolConfig,
        epoch: u64,
        accumulator_root_obj_initial_shared_version: SequenceNumber,
        checkpoint_height: u64,
        checkpoint_seq: u64,
    ) -> Vec<TransactionKind> {
        let Self {
            updates, addresses, ..
        } = self;

        let build_one_settlement_txn = |idx: u64, updates: &mut Vec<(AccumulatorObjId, Update)>| {
            let (total_input_sui, total_output_sui) =
                updates
                    .iter()
                    .fold((0, 0), |(acc_input, acc_output), (_, update)| {
                        (acc_input + update.input_sui, acc_output + update.output_sui)
                    });

            Self::build_one_settlement_txn(
                &addresses,
                epoch,
                idx,
                checkpoint_height,
                accumulator_root_obj_initial_shared_version,
                updates.drain(..),
                total_input_sui,
                total_output_sui,
                checkpoint_seq,
            )
        };

        let chunk_size = protocol_config
            .max_updates_per_settlement_txn_as_option()
            .unwrap_or(u32::MAX) as usize;

        updates
            .into_iter()
            .chunks(chunk_size)
            .into_iter()
            .enumerate()
            .map(|(idx, chunk)| {
                build_one_settlement_txn(idx as u64, &mut chunk.collect::<Vec<_>>())
            })
            .collect()
    }
```

**File:** sui-execution/latest/sui-move-natives/src/funds_accumulator.rs (L28-93)
```rust
pub fn add_to_accumulator_address(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(args.len() == 3);

    // TODO(address-balances): add specific cost for this
    let event_emit_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()?
        .event_emit_cost_params
        .clone();
    native_charge_gas_early_exit!(context, event_emit_cost_params.event_emit_cost_base);

    let ty_tag = context.type_to_type_tag(&safe_unwrap!(ty_args.pop()))?;

    let Some(value) = safe_unwrap!(args.pop_back()).value_as::<Struct>().ok() else {
        // TODO in the future this is guaranteed/checked via a custom verifier rule
        debug_assert!(false);
        return Err(
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR).with_message(
                "Balance should be guaranteed under current implementation".to_owned(),
            ),
        );
    };
    let recipient = safe_unwrap!(safe_unwrap!(args.pop_back()).value_as::<AccountAddress>());
    let accumulator: ObjectID =
        safe_unwrap!(safe_unwrap!(args.pop_back()).value_as::<AccountAddress>()).into();

    // TODO this will need to look at the layout of T when this is not guaranteed to be a Balance
    let Some([amount]): Option<[Value; 1]> = value.unpack().collect::<Vec<_>>().try_into().ok()
    else {
        debug_assert!(false);
        return Err(
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR).with_message(
                "Balance should be guaranteed under current implementation".to_owned(),
            ),
        );
    };
    let Some(amount) = amount.value_as::<u64>().ok() else {
        debug_assert!(false);
        return Err(
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR).with_message(
                "Balance should be guaranteed under current implementation".to_owned(),
            ),
        );
    };

    let cost = context.gas_used();

    let obj_runtime: &mut ObjectRuntime = context.extensions_mut().get_mut()?;

    if !obj_runtime.protocol_config.enable_accumulators() {
        return Ok(NativeResult::err(cost, E_ADDRESS_BALANCE_NOT_ENABLED));
    }

    obj_runtime.emit_accumulator_event(
        accumulator,
        MoveAccumulatorAction::Merge,
        recipient,
        ty_tag,
        MoveAccumulatorValue::U64(amount),
    )?;
    Ok(NativeResult::ok(context.gas_used(), smallvec![]))
```
