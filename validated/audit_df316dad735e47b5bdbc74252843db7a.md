No vulnerability found for this question.

**Analysis**: The `PseudoGasContext` mechanism in `ty_tag_converter.rs` is an internal metering safeguard that bounds the computational cost of converting `Type`s into `TypeTag`s (used e.g. to prevent pathological deeply-nested/generic type blowups), and it is entirely decoupled from real transaction gas accounting, fee-payer binding, or any signer/authenticator logic used in transaction admission.

The specific mechanism cited is not flawed. In `struct_name_idx_to_struct_tag_impl`, the code records `cur_cost` before recursing into type arguments, then computes `pseudo_gas_cost: gas_context.current_cost() - cur_cost` [1](#0-0) . This delta computation is specifically designed to isolate the marginal cost of building *this* struct tag, independent of whatever cost had already accumulated on `gas_context` before entering the function — this is standard "before/after" delta accounting, not a bug. The unit test `test_ty_to_ty_tag_struct_metering` confirms the stored `pseudo_gas_cost` exactly matches the expected marginal cost for a struct tag construction [2](#0-1) .

Even if the arithmetic were flawed, this `TypeTagCache`/`PricedStructTag` structure has no connection to real gas charging, sponsor/fee-payer validation, or authenticator/signer-set binding used in transaction admission — it only governs the complexity limit (`type_max_cost`) applied while converting a VM `Type` into a `TypeTag` string representation [3](#0-2) . It does not touch sender, signer set, sequence number, chain-id, expiry, or gas-payer bindings that define the transaction admission boundary, so this cannot decouple "the gas payer binding from the actual cost incurred" in the sense required by the admission impact gate.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L17-65)
```rust
struct PseudoGasContext {
    // Parameters for metering type tag construction:
    //   - maximum allowed cost,
    //   - base cost for any type to tag conversion,
    //   - cost for size of a struct tag.
    max_cost: u64,
    cost: u64,
    cost_base: u64,
    cost_per_byte: u64,
}

impl PseudoGasContext {
    fn new(vm_config: &VMConfig) -> Self {
        Self {
            max_cost: vm_config.type_max_cost,
            cost: 0,
            cost_base: vm_config.type_base_cost,
            cost_per_byte: vm_config.type_byte_cost,
        }
    }

    fn current_cost(&mut self) -> u64 {
        self.cost
    }

    fn charge_base(&mut self) -> PartialVMResult<()> {
        self.charge(self.cost_base)
    }

    fn charge_struct_tag(&mut self, struct_tag: &StructTag) -> PartialVMResult<()> {
        let size =
            (struct_tag.address.len() + struct_tag.module.len() + struct_tag.name.len()) as u64;
        self.charge(size * self.cost_per_byte)
    }

    fn charge(&mut self, amount: u64) -> PartialVMResult<()> {
        self.cost += amount;
        if self.cost > self.max_cost {
            Err(
                PartialVMError::new(StatusCode::TYPE_TAG_LIMIT_EXCEEDED).with_message(format!(
                    "Exceeded maximum type tag limit of {} when charging {}",
                    self.max_cost, amount
                )),
            )
        } else {
            Ok(())
        }
    }
}
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L357-374)
```rust
        // If not cached, record the current cost and construct tags for type arguments.
        let cur_cost = gas_context.current_cost();

        let type_args = ty_args
            .iter()
            .map(|ty| self.ty_to_ty_tag_impl(ty, gas_context))
            .collect::<PartialVMResult<Vec<_>>>()?;

        // Construct the struct tag as well.
        let struct_name_index_map = self.runtime_environment.struct_name_index_map();
        let struct_tag = struct_name_index_map.idx_to_struct_tag(*struct_name_idx, type_args)?;
        gas_context.charge_struct_tag(&struct_tag)?;

        // Cache the struct tag. Record its gas cost as well.
        let priced_tag = PricedStructTag {
            struct_tag,
            pseudo_gas_cost: gas_context.current_cost() - cur_cost,
        };
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L628-640)
```rust
        let mut gas_context = PseudoGasContext::new(runtime_environment.vm_config());
        assert_ok_eq!(
            ty_tag_converter.struct_name_idx_to_struct_tag_impl(&idx, &[], &mut gas_context),
            struct_tag.clone()
        );

        // Address size, plus module name and struct name each taking 3 characters.
        let expected_cost = 2 * (32 + 3 + 3);
        assert_eq!(gas_context.current_cost(), expected_cost);

        let priced_tag = assert_some!(runtime_environment.ty_tag_cache().get_struct_tag(&idx, &[]));
        assert_eq!(priced_tag.pseudo_gas_cost, expected_cost);
        assert_eq!(priced_tag.struct_tag, struct_tag);
```
