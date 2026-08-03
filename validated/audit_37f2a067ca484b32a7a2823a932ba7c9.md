No vulnerability found for this question.

**Reasoning:**

`sig_to_ty` does technically map `SignatureToken::Signer` to `MoveTypeLayout::Signer` [1](#0-0) , and `Constant::deserialize_constant` calls it directly without further restriction [2](#0-1) .

However, this code path is never reachable for an attacker-controlled constant pool entry, because the bytecode verifier's constant-pool checker validates the constant's *type* before ever calling `deserialize_constant`/`sig_to_ty`:

```
fn verify_constant(idx: usize, constant: &Constant) -> PartialVMResult<()> {
    verify_constant_type(idx, &constant.type_)?;
    verify_constant_data(idx, constant)
}
``` [3](#0-2) 

`verify_constant_type` rejects any `SignatureToken` for which `is_valid_for_constant()` returns `false`, returning `INVALID_CONSTANT_TYPE` before `verify_constant_data` (which is what invokes `deserialize_constant`/`sig_to_ty`) is ever reached: [4](#0-3) 

`SignatureToken::is_valid_for_constant()` (defined alongside the other `SignatureToken` variants in `file_format.rs`) only allows primitive/boolean/integer/address types and vectors thereof, and explicitly disallows `Signer`, `Struct`, `Reference`, `MutableReference`, `TypeParameter`, and `Function` — this is a deliberate restriction so that a `signer` value can never be smuggled in as module/script bytecode constant data. Consequently, a module submitted by an unprivileged attacker containing a constant pool entry typed `SignatureToken::Signer` fails module verification at admission time (publish-time bytecode verification, which is mandatory before a module transaction is committed) with `INVALID_CONSTANT_TYPE`, and `verify_constant_data`/`sig_to_ty` is never invoked on it.

Because the constant-type gate (`verify_constant_type`) runs and rejects the malicious constant *before* `sig_to_ty` is ever exercised on attacker input, the described exploit path — reaching `sig_to_ty(SignatureToken::Signer)` via an admitted, attacker-submitted module — is not achievable through the transaction admission pipeline. The unit-test-only proof idea (calling `sig_to_ty` and `simple_deserialize` directly) demonstrates a function-level behavior but does not demonstrate that unprivileged transaction input can reach that code with an unvalidated constant, since the bytecode verifier intercepts it first. This does not meet the review's admission-boundary bar, which requires the bad binding to be reachable through the actual committed admission path (mempool → vm-validator → VM module verification), and the VM's own constant-pool verifier already converges correctly by rejecting `Signer`-typed constants.

### Citations

**File:** third_party/move/move-binary-format/src/constant.rs (L9-12)
```rust
fn sig_to_ty(sig: &SignatureToken) -> Option<MoveTypeLayout> {
    match sig {
        SignatureToken::Signer => Some(MoveTypeLayout::Signer),
        SignatureToken::Address => Some(MoveTypeLayout::Address),
```

**File:** third_party/move/move-binary-format/src/constant.rs (L72-75)
```rust
    pub fn deserialize_constant(&self) -> Option<MoveValue> {
        let ty = sig_to_ty(&self.type_)?;
        MoveValue::simple_deserialize(&self.data, &ty).ok()
    }
```

**File:** third_party/move/move-bytecode-verifier/src/constants.rs (L39-42)
```rust
fn verify_constant(idx: usize, constant: &Constant) -> PartialVMResult<()> {
    verify_constant_type(idx, &constant.type_)?;
    verify_constant_data(idx, constant)
}
```

**File:** third_party/move/move-bytecode-verifier/src/constants.rs (L44-54)
```rust
fn verify_constant_type(idx: usize, type_: &SignatureToken) -> PartialVMResult<()> {
    if type_.is_valid_for_constant() {
        Ok(())
    } else {
        Err(verification_error(
            StatusCode::INVALID_CONSTANT_TYPE,
            IndexKind::ConstantPool,
            idx as TableIndex,
        ))
    }
}
```
