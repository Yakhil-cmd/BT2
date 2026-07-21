The code is clear. Let me trace the exact path.

**`run_execute` for `DeclareTransaction` (lines 184–189):**

```rust
if context.tx_context.block_context.versioned_constants.block_casm_hash_v1_declares
    && self.version() >= TransactionVersion::THREE
{
    self.check_compile_class_hash_v2_declaration()?
}
try_declare(self, state, class_hash, Some(*compiled_class_hash))?
```

The CASM-hash cross-check (`check_compile_class_hash_v2_declaration`) is **only called when `block_casm_hash_v1_declares == true`**. When the flag is `false`, the check is skipped entirely and the attacker-supplied `compiled_class_hash` is forwarded verbatim to `try_declare`.

**`try_declare` (lines 387–408):**

```rust
state.set_contract_class(class_hash, tx.contract_class().try_into()?)?;
if let Some(compiled_class_hash) = compiled_class_hash {
    state.set_compiled_class_hash(class_hash, compiled_class_hash)?;
}
```

No cross-check. The value is written directly to state.

My search for `compiled_class_hash` in `crates/gateway/**` and `crates/starknet_gateway/**` returned **no matches**, meaning no upstream gateway layer independently validates the `compiled_class_hash` against the actual compiled CASM before the transaction reaches blockifier.

The attacker's own account signs a DeclareV3 where `compiled_class_hash = arbitrary_felt`. The signature is valid because the Starknet transaction hash for DeclareV3 **includes** `compiled_class_hash` as a signed field — the account signs whatever hash the transaction commits to, so signature validation passes regardless of the `compiled_class_hash` value.

---

### Title
Attacker-controlled `compiled_class_hash` stored to state unchecked in DeclareV3 when `block_casm_hash_v1_declares=false` — (`crates/blockifier/src/transaction/transactions.rs`)

### Summary
When the versioned-constants flag `block_casm_hash_v1_declares` is `false`, the blockifier's `run_execute` path for `DeclareTransaction` skips the only CASM-hash integrity check (`check_compile_class_hash_v2_declaration`) and passes the transaction-supplied `compiled_class_hash` directly to `try_declare`, which writes it to state with `set_compiled_class_hash` without any cross-validation against the actual compiled CASM.

### Finding Description
In `Executable<S> for DeclareTransaction::run_execute`, the guard at line 184 is:

```rust
if context.tx_context.block_context.versioned_constants.block_casm_hash_v1_declares
    && self.version() >= TransactionVersion::THREE
{
    self.check_compile_class_hash_v2_declaration()?
}
``` [1](#0-0) 

When `block_casm_hash_v1_declares == false`, the entire `if`-body is skipped. Execution falls through unconditionally to:

```rust
try_declare(self, state, class_hash, Some(*compiled_class_hash))?
``` [2](#0-1) 

Inside `try_declare`, for an undeclared class, the code writes:

```rust
state.set_compiled_class_hash(class_hash, compiled_class_hash)?;
``` [3](#0-2) 

There is no other validation site. The gateway crates contain no independent check of `compiled_class_hash` against the class manager output.

### Impact Explanation
The `compiled_class_hash` committed to the state diff is the attacker-chosen arbitrary felt, not the hash of the CASM actually compiled from the Sierra class. The OS proof system reads `compiled_class_hash` from the state diff to verify class commitments; a wrong value causes the proof to bind the wrong CASM to the class hash. This is a **Critical** impact: wrong compiled class hash committed to state diff, OS proof uses wrong hash. [4](#0-3) 

### Likelihood Explanation
Exploitable by any unprivileged user who can submit a DeclareV3 transaction to a sequencer running with `block_casm_hash_v1_declares=false`. The attacker's account signs the transaction hash, which includes the `compiled_class_hash` field, so signature validation passes for any arbitrary value. No special privileges are required.

### Recommendation
Remove the flag guard so that `check_compile_class_hash_v2_declaration` is always called for V2/V3 declare transactions, regardless of `block_casm_hash_v1_declares`. If the flag must remain for migration purposes, it should only suppress the check for V1/V2 transactions (as the name implies), never for V3.

### Proof of Concept
1. Construct a `DeclareTransaction::V3` with `compiled_class_hash = Felt::from(0xdeadbeef)` and a valid Sierra class whose actual CASM hash differs.
2. Set `block_casm_hash_v1_declares = false` in versioned constants.
3. Call `run_execute` on the transaction against a `CachedState`.
4. Assert `state.get_compiled_class_hash(class_hash) == CompiledClassHash(Felt::from(0xdeadbeef))`.

The assertion holds because the guard at line 184 is not entered, `try_declare` is called with the arbitrary felt, and `set_compiled_class_hash` writes it to state without any cross-check. [5](#0-4)

### Citations

**File:** crates/blockifier/src/transaction/transactions.rs (L155-193)
```rust
impl<S: State> Executable<S> for DeclareTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        context: &mut EntryPointExecutionContext,
        _remaining_gas: &mut u64,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let class_hash = self.class_hash();
        match &self.tx {
            starknet_api::transaction::DeclareTransaction::V0(_)
            | starknet_api::transaction::DeclareTransaction::V1(_) => {
                if context.tx_context.block_context.versioned_constants.disable_cairo0_redeclaration
                {
                    try_declare(self, state, class_hash, None)?
                } else {
                    // We allow redeclaration of the class for backward compatibility.
                    // In the past, we allowed redeclaration of Cairo 0 contracts since there was
                    // no class commitment (so no need to check if the class is already declared).
                    state.set_contract_class(class_hash, self.contract_class().try_into()?)?;
                }
            }
            starknet_api::transaction::DeclareTransaction::V2(DeclareTransactionV2 {
                compiled_class_hash,
                ..
            })
            | starknet_api::transaction::DeclareTransaction::V3(DeclareTransactionV3 {
                compiled_class_hash,
                ..
            }) => {
                if context.tx_context.block_context.versioned_constants.block_casm_hash_v1_declares
                    && self.version() >= TransactionVersion::THREE
                {
                    self.check_compile_class_hash_v2_declaration()?
                }
                try_declare(self, state, class_hash, Some(*compiled_class_hash))?
            }
        }
        Ok(None)
    }
```

**File:** crates/blockifier/src/transaction/transactions.rs (L387-408)
```rust
fn try_declare<S: State>(
    tx: &DeclareTransaction,
    state: &mut S,
    class_hash: ClassHash,
    compiled_class_hash: Option<CompiledClassHash>,
) -> TransactionExecutionResult<()> {
    match state.get_compiled_class(class_hash) {
        Err(StateError::UndeclaredClassHash(_)) => {
            // Class is undeclared; declare it.
            state.set_contract_class(class_hash, tx.contract_class().try_into()?)?;
            if let Some(compiled_class_hash) = compiled_class_hash {
                state.set_compiled_class_hash(class_hash, compiled_class_hash)?;
            }
            Ok(())
        }
        Err(error) => Err(error)?,
        Ok(_) => {
            // Class is already declared, cannot redeclare.
            Err(TransactionExecutionError::DeclareTransactionError { class_hash })
        }
    }
}
```
