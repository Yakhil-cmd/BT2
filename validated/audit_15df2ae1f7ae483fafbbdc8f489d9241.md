[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/ty_depth_checker.rs (L145-209)
```rust
        let ty_depth = match ty {
            Type::Bool
            | Type::U8
            | Type::U16
            | Type::U32
            | Type::U64
            | Type::U128
            | Type::U256
            | Type::I8
            | Type::I16
            | Type::I32
            | Type::I64
            | Type::I128
            | Type::I256
            | Type::Address
            | Type::Signer => check_depth!(0),
            // For function types, we ignore the return/argument types because they do not bound
            // value size, and we do not to error on a false positive (function operates on a
            // nested value, but does not capture it).
            Type::Function { .. } => check_depth!(0),
            Type::Reference(ty) | Type::MutableReference(ty) => self
                .recursive_check_depth_of_type(
                    gas_meter,
                    traversal_context,
                    ty,
                    max_depth,
                    check_depth!(1),
                )?,
            Type::Vector(ty) => self.recursive_check_depth_of_type(
                gas_meter,
                traversal_context,
                ty,
                max_depth,
                check_depth!(1),
            )?,
            Type::Struct { idx, .. } => {
                let formula = visit_struct!(idx);
                let depth = formula.solve(&[])?;
                check_depth!(depth)
            },
            Type::StructInstantiation { idx, ty_args, .. } => {
                let ty_arg_depths = ty_args
                    .iter()
                    .map(|ty| {
                        self.recursive_check_depth_of_type(
                            gas_meter,
                            traversal_context,
                            ty,
                            max_depth,
                            check_depth!(0),
                        )
                    })
                    .collect::<PartialVMResult<Vec<_>>>()?;

                let formula = visit_struct!(idx);
                let depth = formula.solve(&ty_arg_depths)?;
                check_depth!(depth)
            },
            Type::TyParam(_) => {
                return Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message("Type parameter should be fully resolved".to_string()),
                )
            },
        };
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_depth_checker.rs (L382-396)
```rust
// Test-only interfaces below.
#[cfg(test)]
impl<'a, T> TypeDepthChecker<'a, T>
where
    T: StructDefinitionLoader,
{
    /// Creates a new depth checker for the specified loader and with specified maximum depth.
    fn new_with_max_depth(struct_definition_loader: &'a T, max_depth: u64) -> Self {
        Self {
            struct_definition_loader,
            maybe_max_depth: Some(max_depth),
            formula_cache: RefCell::new(HashMap::new()),
        }
    }
}
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_depth_checker.rs (L697-748)
```rust
    #[test]
    fn test_ty_to_deep() {
        let mut gas_meter = UnmeteredGasMeter;
        let traversal_storage = TraversalStorage::new();
        let mut traversal_context = TraversalContext::new(&traversal_storage);

        let loader = MockStructDefinitionLoader::default();

        let a = loader.get_struct_identifier("A");
        let b = loader.get_struct_identifier("B");
        let c = loader.get_struct_identifier("C");

        loader.add_struct("C", vec![("dummy", Type::Bool)]);
        loader.add_struct("B", vec![("c", struct_ty(c))]);
        loader.add_struct("A", vec![("b", struct_ty(b))]);

        let checker = TypeDepthChecker::new_with_max_depth(&loader, 2);

        assert_ok!(checker.check_depth_of_type(&mut gas_meter, &mut traversal_context, &Type::U8));

        let vec_u8_ty = Type::Vector(triomphe::Arc::new(Type::U8));
        assert_ok!(checker.check_depth_of_type(&mut gas_meter, &mut traversal_context, &vec_u8_ty));

        let vec_vec_u8_ty = Type::Vector(triomphe::Arc::new(vec_u8_ty.clone()));
        assert_err!(checker.check_depth_of_type(
            &mut gas_meter,
            &mut traversal_context,
            &vec_vec_u8_ty
        ));
        let ref_vec_u8_ty = Type::Reference(Box::new(vec_u8_ty));
        assert_err!(checker.check_depth_of_type(
            &mut gas_meter,
            &mut traversal_context,
            &ref_vec_u8_ty
        ));

        assert_ok!(checker.check_depth_of_type(
            &mut gas_meter,
            &mut traversal_context,
            &struct_ty(c)
        ));
        assert_err!(checker.check_depth_of_type(
            &mut gas_meter,
            &mut traversal_context,
            &struct_ty(b)
        ));
        assert_err!(checker.check_depth_of_type(
            &mut gas_meter,
            &mut traversal_context,
            &struct_ty(a)
        ));
    }
```
