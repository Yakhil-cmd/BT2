Audit Report

## Title
Compilation Cache Poisoning via Distinct Malformed Gzip Modules in `install_code` — (`rs/execution_environment/src/hypervisor.rs`, `rs/embedders/src/compilation_cache.rs`)

## Summary
`Hypervisor::create_execution_state` calls `decoded_wasm_size` before invoking the wasm executor. When the result is `Err` (e.g., a ≤15-byte gzip-prefixed buffer), it immediately calls `self.compilation_cache.insert_err` and returns early. `insert_err` unconditionally pushes an `Err` entry into the shared 500,000-entry LRU cache, evicting the least-recently-used entry — which may be a valid compiled module for a legitimate canister. An unprivileged attacker with enough cycles can flood the cache with distinct error entries, forcing continuous recompilation for all canisters on the subnet and measurably degrading throughput.

## Finding Description
In `rs/execution_environment/src/hypervisor.rs` at lines 155–166, `decoded_wasm_size` is called on the raw module bytes. For any buffer starting with `\x1f\x8b\x08` (gzip magic) that is fewer than 16 bytes, `wasm_encoding_and_size` in `rs/embedders/src/wasm_utils/decoding.rs` (lines 26–31) returns `Err(WasmValidationError::DecodingError(...))`. Back in `create_execution_state`, the `if let Err(err) = wasm_size_result` branch at lines 161–166 calls `self.compilation_cache.insert_err(&canister_module, err.clone().into())` and returns before the wasm executor is ever invoked.

`insert_err` in `rs/embedders/src/compilation_cache.rs` (lines 106–112) acquires the cache lock, pops the LRU entry if `cache.len() >= max_entries`, and pushes the new `Err` entry. `DEFAULT_MAX_ENTRIES` is 500,000 (line 22). Error entries and valid compiled-module entries share the same LRU map with no separation or quota. Each distinct malformed module (different bytes → different `WasmHash`) occupies one slot and evicts one valid entry.

The rate limit in `rs/execution_environment/src/execution/install_code.rs` (lines 895–897) accumulates `install_code_debit` per canister and is checked per canister in `rs/execution_environment/src/scheduler/round_schedule.rs` (lines 310–322). An attacker controlling N canisters can submit one `install_code` per round per canister, generating N distinct error entries per round. With 1,000 canisters, the 500,000-entry cache can be saturated in ~500 rounds.

## Impact Explanation
Once the cache is saturated with error entries, every `compilation_cache.get` for a legitimate canister returns `None`, triggering a full recompile on every `install_code` or first execution. Recompilation is the most expensive part of `install_code` and first-execution setup. Sustained poisoning forces continuous recompilation for all canisters on the subnet, constituting a subnet availability impact — specifically application/platform-level throughput degradation not based on raw volumetric DDoS. This maps to the **High ($2,000–$10,000)** impact class.

## Likelihood Explanation
The attack requires only the ability to create canisters and call `install_code` (open to any principal with cycles) and enough cycles to create ~1,000 canisters (~100T cycles) and pay per-call execution costs. The per-call cost for a 15-byte module is minimal (base cost + `cost_to_compile_wasm_instruction × 15`). The per-canister rate limit is trivially bypassed by spreading calls across many canisters. The attack is locally testable, repeatable, and does not require any special privileges or insider access.

## Recommendation
1. **Do not cache decoding errors.** `WasmValidationError::DecodingError` results are cheap to reproduce and carry no compilation work; they should not occupy cache slots. Remove the `insert_err` call in the `wasm_size_result` error branch in `Hypervisor::create_execution_state` (`rs/execution_environment/src/hypervisor.rs`, lines 164–165).
2. **Separate error entries from compiled-module entries** in the LRU, or cap error entries at a small fixed fraction of `max_entries`, so they cannot evict valid compiled modules.
3. **Charge cycles proportional to actual work done** for malformed-module submissions to raise the economic cost of cache flooding.

## Proof of Concept
```python
# Requires N canisters already created with sufficient cycles.
# Each iteration submits a distinct 15-byte gzip-prefixed module.
for i in range(500_000):
    # 3-byte gzip magic + 12 unique bytes = 15 bytes total, distinct hash per i
    payload = b"\x1f\x8b\x08" + i.to_bytes(12, 'little')
    install_code(canister_id=canister_pool[i % N], wasm_module=payload)

# Measure compilation cache hit rate for a legitimate canister before and after.
# Expected: hit rate drops from ~100% to ~0%, forcing full recompile on every execution.
```
A deterministic integration test can verify this by: (1) installing a valid module and confirming a cache hit on re-install, (2) flooding the cache with 500,000 distinct 15-byte gzip-prefixed modules via `install_code`, and (3) re-installing the valid module and confirming a cache miss (recompilation triggered).