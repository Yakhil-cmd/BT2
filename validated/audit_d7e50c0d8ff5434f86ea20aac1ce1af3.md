[1](#0-0) [2](#0-1)

### Citations

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/spanned.rs (L20-32)
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
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/loading/translate.rs (L91-106)
```rust
        CallArg::Object(ObjectArg::Receiving(oref)) => {
            (L::InputArg::Receiving(oref), L::InputType::Bytes)
        }
        CallArg::Object(ObjectArg::ImmOrOwnedObject(oref)) => {
            let id = &oref.0;
            let obj = env.read_object(id)?;
            let Some(ty) = obj.type_() else {
                invariant_violation!("Object {:?} has does not have a Move type", id);
            };
            let tag: StructTag = ty.clone().into();
            let ty = env.load_type_from_struct(&tag)?;
            let arg = match &obj.owner {
                Owner::AddressOwner(_) => L::ObjectArg {
                    kind: L::ObjectArgKind::OwnedObject(oref),
                    refined_permissions: ObjectPermissions::ALL,
                },
```
