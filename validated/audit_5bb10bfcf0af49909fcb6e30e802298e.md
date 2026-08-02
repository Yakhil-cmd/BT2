[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [1](#0-0) [2](#0-1) [5](#0-4) [6](#0-5)

### Citations

**File:** third_party/move/move-vm/runtime/src/frame_type_cache.rs (L212-224)
```rust
    pub(crate) fn get_signature_index_type(
        &mut self,
        idx: SignatureIndex,
        frame: &Frame,
    ) -> PartialVMResult<(&Type, NumTypeNodes, usize)> {
        let (ty, ty_count, depth) = get_or_insert!(&mut self.single_sig_token_type, idx, {
            let ty = frame.instantiate_single_type(idx)?;
            let (ty_count, depth) = ty.num_nodes_with_max_depth();
            let ty_count = NumTypeNodes::new(ty_count as u64);
            (ty, ty_count, depth)
        });
        Ok((ty, *ty_count, *depth))
    }
```

**File:** third_party/move/move-vm/runtime/src/frame_type_cache.rs (L230-238)
```rust
    pub(crate) fn make_rc_for_function(function: &LoadedFunction) -> Rc<RefCell<Self>> {
        let frame_cache = Rc::new(RefCell::<Self>::new(Default::default()));

        frame_cache
            .borrow_mut()
            .per_instruction_cache
            .resize(function.code_size(), PerInstructionCache::Nothing);
        frame_cache
    }
```

**File:** third_party/move/move-vm/runtime/src/frame.rs (L149-185)
```rust
    pub(crate) fn make_new_frame<RTTCheck: RuntimeTypeCheck>(
        gas_meter: &mut impl GasMeter,
        call_type: CallType,
        vm_config: &VMConfig,
        function: Rc<LoadedFunction>,
        guard: Option<FnGuard>,
        locals: Locals,
        frame_cache: Rc<RefCell<FrameTypeCache>>,
        stack: &Stack,
    ) -> PartialVMResult<Frame> {
        let ty_args = function.ty_args();

        let ty_builder = vm_config.ty_builder.clone();
        let local_tys = if ty_args.is_empty() {
            // Function is not generic - avoid cloning types.
            for ty in function.local_tys() {
                gas_meter.charge_create_ty(NumTypeNodes::new(ty.num_nodes() as u64))?;
            }

            if RTTCheck::should_perform_checks(&function.function) {
                LocalTys::BorrowFromFunction
            } else {
                LocalTys::None
            }
        } else {
            // Try cached instantiated locals in frame cache. This way we instantiate only once per
            // usage of the function.
            let mut cache_borrow = frame_cache.borrow_mut();
            if let Some(local_ty_counts) = cache_borrow.instantiated_local_ty_counts.as_ref() {
                for cnt in local_ty_counts.iter() {
                    gas_meter.charge_create_ty(*cnt)?;
                }
            } else {
                let local_tys = function.local_tys();
                let mut local_ty_counts = Vec::with_capacity(local_tys.len());
                for ty in local_tys {
                    let (num_nodes, depth) = ty.num_nodes_in_subst(ty_args)?;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L3122-3132)
```rust
                    Instruction::VecPack(si, num) => {
                        let (ty, ty_count, depth) =
                            frame_cache.get_signature_index_type(*si, self)?;
                        if self.ty_builder.check_depth_on_type_counts_v2 {
                            // Account for new vector node.
                            self.ty_builder.check_final_size_and_depth(
                                u64::from(ty_count) + 1,
                                depth as u64 + 1,
                            )?;
                        }
                        gas_meter.charge_create_ty(ty_count)?;
```
