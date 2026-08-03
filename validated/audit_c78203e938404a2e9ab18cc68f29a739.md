[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** third_party/move/move-vm/runtime/src/interpreter_caches.rs (L17-20)
```rust
pub struct InterpreterFunctionCaches {
    function_instruction_caches: HashMap<FunctionPtr, Rc<RefCell<FrameTypeCache>>>,
    generic_function_instruction_caches: HashMap<GenericFunctionPtr, Rc<RefCell<FrameTypeCache>>>,
}
```

**File:** third_party/move/move-vm/runtime/src/frame_type_cache.rs (L24-63)
```rust
#[derive(Clone)]
pub(crate) enum PerInstructionCache {
    Nothing,
    // Instruction cache is part of the frame cache, so it has to store weak references to prevent
    // memory leaks for recursive functions.
    Call(Rc<LoadedFunction>, Weak<RefCell<FrameTypeCache>>),
    CallGeneric(Rc<LoadedFunction>, Weak<RefCell<FrameTypeCache>>),
}

#[derive(Default)]
pub(crate) struct FrameTypeCache {
    struct_field_type_instantiation:
        BTreeMap<StructDefInstantiationIndex, Vec<(Type, NumTypeNodes)>>,
    struct_variant_field_type_instantiation:
        BTreeMap<StructVariantInstantiationIndex, Vec<(Type, NumTypeNodes)>>,
    struct_def_instantiation_type: BTreeMap<StructDefInstantiationIndex, (Type, NumTypeNodes)>,
    struct_variant_instantiation_type:
        BTreeMap<StructVariantInstantiationIndex, (Type, NumTypeNodes)>,
    /// For a given field instantiation, the:
    ///    ((Type of the field, size of the field type) and (Type of its defining struct,
    ///    size of its defining struct)
    field_instantiation:
        BTreeMap<FieldInstantiationIndex, ((Type, NumTypeNodes), (Type, NumTypeNodes))>,
    /// Same as above, but for variant field instantiations
    variant_field_instantiation:
        BTreeMap<VariantFieldInstantiationIndex, ((Type, NumTypeNodes), (Type, NumTypeNodes))>,
    /// Maps signature index to a tuple of (Type, NumTypeNodes, depth) for single signature tokens.
    /// This cache stores instantiated types for signatures with a single type parameter.
    single_sig_token_type: BTreeMap<SignatureIndex, (Type, NumTypeNodes, usize)>,
    /// Stores a variant for each individual instruction in the
    /// function's bytecode. We keep the size of the variant to be
    /// small. The caches are indexed by the index of the given
    /// bytecode instruction in the function body.
    ///
    /// Important! - If entry is present for a given instruction, then
    /// we do NOT need to re-check for any errors that only depend on
    /// the argument of the bytecode instructions, for which it is
    /// guaranteed that everything will be exactly the same as when we
    /// did the insertion.
    pub(crate) per_instruction_cache: Vec<PerInstructionCache>,
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs (L706-750)
```rust
    /// For a given function instantiation index, loads it instantiation, and its frame cache.
    fn load_function_generic(
        &mut self,
        current_frame: &mut Frame,
        idx: FunctionInstantiationIndex,
    ) -> PartialVMResult<(Rc<LoadedFunction>, Rc<RefCell<FrameTypeCache>>)> {
        let pc = current_frame.pc as usize;
        let current_frame_cache = &mut *current_frame.frame_cache.borrow_mut();

        let function_and_cache = if let PerInstructionCache::CallGeneric(function, frame_cache) =
            &current_frame_cache.per_instruction_cache[pc]
        {
            let frame_cache = frame_cache.upgrade().ok_or_else(|| {
                PartialVMError::new_invariant_violation(
                    "Frame cache is dropped during interpreter execution",
                )
            })?;
            (Rc::clone(function), frame_cache)
        } else {
            let (function, frame_cache) =
                match current_frame_cache.generic_function_cache.entry(idx) {
                    Entry::Vacant(e) => {
                        let function =
                            self.instantiation_idx_to_loaded_function(current_frame, idx)?;
                        let frame_cache = self
                            .function_caches
                            .get_or_create_frame_cache_generic(&function);
                        e.insert((function.clone(), Rc::downgrade(&frame_cache)));
                        (function, frame_cache)
                    },
                    Entry::Occupied(e) => {
                        let (function, frame_cache) = e.get();
                        let frame_cache = frame_cache.upgrade().ok_or_else(|| {
                            PartialVMError::new_invariant_violation(
                                "Frame cache is dropped during interpreter execution",
                            )
                        })?;
                        (function.clone(), frame_cache)
                    },
                };

            current_frame_cache.per_instruction_cache[pc] =
                PerInstructionCache::CallGeneric(Rc::clone(&function), Rc::downgrade(&frame_cache));
            (function, frame_cache)
        };
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs (L754-784)
```rust
    /// Converts handle to a non-generic function into a [LoadedFunction].
    fn idx_to_loaded_function(
        &self,
        frame: &Frame,
        idx: FunctionHandleIndex,
    ) -> PartialVMResult<Rc<LoadedFunction>> {
        let handle = match frame.function.owner() {
            LoadedFunctionOwner::Script(script) => script.function_at(idx.0),
            LoadedFunctionOwner::Module(module) => module.function_at(idx.0),
        };
        let no_ty_args_id = self.ty_pool.intern_ty_args(&[]);
        self.handle_to_loaded_function(frame, handle, vec![], no_ty_args_id)
    }

    /// Converts handle to an instantiation of a generic function into a [LoadedFunction].
    fn instantiation_idx_to_loaded_function(
        &self,
        frame: &Frame,
        idx: FunctionInstantiationIndex,
    ) -> PartialVMResult<Rc<LoadedFunction>> {
        let handle = match frame.function.owner() {
            LoadedFunctionOwner::Script(script) => script.function_instantiation_handle_at(idx.0),
            LoadedFunctionOwner::Module(module) => module.function_instantiation_handle_at(idx.0),
        };
        let (ty_args, ty_args_id) = frame.instantiate_generic_function(
            self.ty_pool,
            None::<&mut UnmeteredGasMeter>,
            idx,
        )?;
        self.handle_to_loaded_function(frame, handle, ty_args, ty_args_id)
    }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L429-478)
```rust
                ExitCode::Call(fh_idx) => {
                    let (function, frame_cache) = if self.vm_config.enable_function_caches {
                        let current_frame_cache = &mut *current_frame.frame_cache.borrow_mut();

                        if let PerInstructionCache::Call(ref function, ref frame_cache) =
                            current_frame_cache.per_instruction_cache[current_frame.pc as usize]
                        {
                            let frame_cache = frame_cache.upgrade().ok_or_else(|| {
                                PartialVMError::new_invariant_violation(
                                    "Frame cache is dropped during interpreter execution",
                                )






























                                    },
                                };
                            current_frame_cache.per_instruction_cache[current_frame.pc as usize] =
                                PerInstructionCache::Call(
                                    Rc::clone(&function),
                                    Rc::downgrade(&frame_cache),
                                );
                            (function, frame_cache)
                        }
```
