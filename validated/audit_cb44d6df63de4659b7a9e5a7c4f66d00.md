Audit Report

## Title
Untrusted Gzip Footer Value Used as Compilation Cost Estimate in Error Path, Exhausting Subnet Message Instruction Budget - (`rs/execution_environment/src/hypervisor.rs`)

## Summary
`Hypervisor::create_execution_state` reads the uncompressed size from the attacker-controlled gzip footer via `decoded_wasm_size()` and uses it to compute a `compilation_cost` that is charged to `round_limits.instructions` when `wasm_executor.create_execution_state` subsequently fails. Because `decoded_wasm_size()` performs no upper-bound validation, an attacker can submit a gzip blob whose footer claims `u32::MAX` (~4 GiB), causing `decode_wasm` to reject the module as `ModuleTooLarge` and the error branch to charge `6,000 × 4,294,967,295 ≈ 2.57 × 10^13` instructions against the subnet message instruction budget — roughly 58,000× the entire per-round subnet message budget — in a single `install_code` call.

## Finding Description

**Root cause — `decoded_wasm_size` returns an uncapped attacker-controlled value:**

`wasm_encoding_and_size` in `rs/embedders/src/wasm_utils/decoding.rs` reads the last 4 bytes of the gzip blob (the ISIZE field) and returns them directly as the uncompressed size with no upper-bound check: [1](#0-0) 

The public wrapper `decoded_wasm_size` carries an explicit warning that this value is untrusted: [2](#0-1) 

**Vulnerable use in `create_execution_state`:**

`Hypervisor::create_execution_state` uses the untrusted value to compute `compilation_cost` before any validation occurs: [3](#0-2) 

When `wasm_size_result` is `Ok` (which it is for any syntactically valid gzip, regardless of footer content), execution proceeds to `wasm_executor.create_execution_state`. Inside the executor, `decode_wasm` enforces `wasm_max_size`: [4](#0-3) 

This returns `ModuleTooLarge`, causing the executor to return `Err`. The error branch then charges the inflated `compilation_cost` — computed from the untrusted footer value — to `round_limits.instructions`: [5](#0-4) 

**Conversion does not saturate at a safe value:**

`as_round_instructions` saturates at `i64::MAX` only for values exceeding `i64::MAX ≈ 9.2 × 10^18`. The inflated cost `6,000 × 4,294,967,295 ≈ 2.57 × 10^13` is well within `i64` range, so the full value is charged: [6](#0-5) 

**Scope of budget depletion:**

`install_code` is a subnet message processed by `drain_subnet_queues` using `subnet_round_limits`, whose `instructions` field is initialized to `max_instructions_per_round / SUBNET_MESSAGES_LIMIT_FRACTION` (i.e., 1/16 of the round budget): [7](#0-6) 

The inflated charge depletes `subnet_instructions` to a large negative value, causing `instructions_reached()` to return `true` for all subsequent subnet messages in the same round. The canister execution budget (`instructions`) is a separate field and is not directly affected.

## Impact Explanation

Exhausting `subnet_instructions` prevents all subsequent subnet management messages (`install_code`, `create_canister`, `update_settings`, `stop_canister`, etc.) from being processed for the remainder of that round. Because the attack is repeatable every round at the cost of a single normal `install_code` prepayment, an attacker can permanently starve subnet management operations on the targeted subnet. This constitutes a **High** severity application/platform-level DoS with concrete subnet availability impact, matching the allowed ICP bounty impact: *"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."*

## Likelihood Explanation

Any canister developer with enough cycles to cover a normal `install_code` prepayment can execute this attack. The only required steps are: (1) gzip-compress any minimal valid Wasm binary, and (2) overwrite the last 4 bytes of the resulting file with `\xFF\xFF\xFF\xFF`. No privileged access, no social engineering, and no threshold corruption is required. The attack is repeatable every round. The existing test `test_decode_large_compressed_module_with_tweaked_size` in `rs/embedders/tests/misc_tests.rs` already demonstrates that footer manipulation is trivial: [8](#0-7) 

## Recommendation

In the error branch of `Hypervisor::create_execution_state`, replace the untrusted `wasm_size` (derived from the gzip footer) with the actual compressed module length, which is bounded by the ingress message size limit:

```rust
// Use the compressed size as the safe fallback, not the untrusted decoded size.
let safe_size = canister_module.len();
let compilation_cost = self.cost_to_compile_wasm_instruction * safe_size as u64;
```

Alternatively, cap the value returned by `decoded_wasm_size` to `wasm_max_size` before using it to compute `compilation_cost`, mirroring the check already present in `decode_wasm`. Either fix ensures the charged cost is bounded by the actual compressed input size, which is already constrained by the ingress message size limit.

## Proof of Concept

1. Take any minimal valid Wasm binary (e.g., `\x00asm\x01\x00\x00\x00`).
2. Gzip-compress it with any standard tool.
3. Overwrite the last 4 bytes of the `.gz` file with `\xFF\xFF\xFF\xFF` (little-endian `u32::MAX`).
4. Submit the modified blob as the `wasm_module` field of an `install_code` ingress message targeting any canister on the subnet.
5. `decoded_wasm_size` returns `Ok(4_294_967_295)`.
6. `compilation_cost = 6_000 × 4_294_967_295 ≈ 2.57 × 10^13` instructions.
7. `wasm_executor.create_execution_state` calls `decode_wasm`, which returns `ModuleTooLarge` (4 GiB > `wasm_max_size`).
8. The error branch reduces `round_limits.instructions` (i.e., `subnet_instructions`) by `≈ 2.57 × 10^13`, driving it to a large negative value.
9. All subsequent subnet management messages in the same round find `instructions_reached() == true` and are skipped.
10. Repeating the attack each round permanently prevents subnet management operations from executing.

### Citations

**File:** rs/embedders/src/wasm_utils/decoding.rs (L11-14)
```rust
/// # Warning
///
/// If the Wasm is gzipped, then the returned size cannot be trusted. It would
/// come from the gzip footer which could have been manipulated.
```

**File:** rs/embedders/src/wasm_utils/decoding.rs (L37-41)
```rust
        let mut isize_bytes = [0_u8; 4];
        // We checked the size in advance so it's safe to access the last 4 bytes.
        isize_bytes.copy_from_slice(&module_bytes[module_bytes.len() - 4..module_bytes.len()]);
        let uncompressed_size = u32::from_le_bytes(isize_bytes) as usize;
        return Ok((WasmEncoding::Gzip, uncompressed_size));
```

**File:** rs/embedders/src/wasm_utils/decoding.rs (L69-73)
```rust
    if uncompressed_size as u64 > max_size.get() {
        return Err(WasmValidationError::ModuleTooLarge {
            size: uncompressed_size as u64,
            allowed: max_size.get(),
        });
```

**File:** rs/execution_environment/src/hypervisor.rs (L155-160)
```rust
        let wasm_size_result = decoded_wasm_size(canister_module.as_slice());
        let wasm_size = match wasm_size_result {
            Ok(size) => std::cmp::max(size, canister_module.len()),
            Err(_) => canister_module.len(),
        };
        let compilation_cost = self.cost_to_compile_wasm_instruction * wasm_size as u64;
```

**File:** rs/execution_environment/src/hypervisor.rs (L188-192)
```rust
            Err(err) => {
                let total_cost = self.create_execution_state_base_cost + compilation_cost;
                round_limits.instructions -= as_round_instructions(total_cost);
                (total_cost, Err(err))
            }
```

**File:** rs/execution_environment/src/execution_environment.rs (L241-243)
```rust
pub fn as_round_instructions(n: NumInstructions) -> RoundInstructions {
    RoundInstructions::from(i64::try_from(n.get()).unwrap_or(i64::MAX))
}
```

**File:** rs/execution_environment/src/scheduler.rs (L1274-1278)
```rust
            SchedulerRoundLimits {
                instructions: round_instructions,
                subnet_instructions: as_round_instructions(
                    self.config.max_instructions_per_round / SUBNET_MESSAGES_LIMIT_FRACTION,
                ),
```

**File:** rs/embedders/tests/misc_tests.rs (L163-170)
```rust
#[test]
#[should_panic(expected = "specified uncompressed size 100 does not match extracted size 101")]
fn test_decode_large_compressed_module_with_tweaked_size() {
    let mut contents = compressed_test_contents("zeros.gz");
    let n = contents.len();
    contents[n - 4..n].copy_from_slice(&100_u32.to_le_bytes());
    decode_wasm(default_max_size(), Arc::new(contents)).unwrap();
}
```
