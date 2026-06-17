### Title
Off-by-One in `SliceVec::resize` Causes Valid EVM Memory Expansions to Fail as Out-of-Gas — (`File: zk_ee/src/memory/slice_vec.rs`)

### Summary

`SliceVec::resize` uses a strict `>=` guard instead of `>` when checking whether the requested new length exceeds the backing capacity. This causes any memory expansion that would exactly fill the backing buffer to be rejected with `Err(())`, which the EVM heap-resize path maps to `OutOfGas`. A transaction that should succeed — because it has sufficient gas and its memory access is within the EVM-defined limit — will instead be aborted with a false out-of-gas error.

### Finding Description

`SliceVec<T>` is a fixed-capacity vector backed by a borrowed `&mut [MaybeUninit<T>]` slice. Its `resize` method guards against overflow with:

```rust
// zk_ee/src/memory/slice_vec.rs:78
if new_length >= self.memory.len() {
    return Err(());
}
``` [1](#0-0) 

The condition should be `> self.memory.len()` (strict greater-than). Using `>=` means that requesting `new_length == self.memory.len()` — i.e., using every slot of the backing buffer — is incorrectly treated as an overflow and returns `Err(())`.

The EVM heap is a `SliceVec<'a, u8>`. Every memory-touching opcode (`MLOAD`, `MSTORE`, `MSTORE8`, `CALLDATACOPY`, `CODECOPY`, `RETURNDATACOPY`, `SHA3`, `MCOPY`, `LOG*`, `CALL`/`CREATE` with memory args) calls `resize_heap_implementation`:

```rust
// evm_interpreter/src/utils.rs:72-93
pub(crate) fn resize_heap_implementation<'a>(
    heap: &mut SliceVec<'a, u8>,
    gas: &mut Gas<S>,
    offset: usize,
    len: usize,
) -> Result<(), ExitCode> {
    let max_offset = offset.saturating_add(len);
    let new_heap_size = ...max_offset.next_multiple_of(32);
    let current_heap_size = heap.len();
    if new_heap_size > current_heap_size {
        gas.pay_for_memory_growth(current_heap_size, new_heap_size)?;
        heap.resize(new_heap_size, 0)
            .map_err(|_| ExitCode::EvmError(EvmError::OutOfGas))?;  // ← false OOG
    }
    Ok(())
}
``` [2](#0-1) 

When `new_heap_size == heap.memory.len()` (the backing buffer is exactly full), `SliceVec::resize` returns `Err(())`, which is mapped to `EvmError::OutOfGas`. The transaction is aborted and all remaining gas is consumed, even though the access is within the EVM-defined memory limit and the caller paid the correct gas.

The EVM memory limit check in `resize_heap_implementation` only rejects accesses beyond `u32::MAX - 31`:

```rust
// evm_interpreter/src/utils.rs:79-81
let new_heap_size = if max_offset > ((u32::MAX - 31) as usize) {
    return Err(ExitCode::EvmError(EvmError::MemoryLimitOOG));
} else { ... };
``` [3](#0-2) 

So the EVM-level limit is correctly enforced, but the `SliceVec` layer imposes an additional, undocumented one-byte-short limit that is invisible to the caller.

### Impact Explanation

Any EVM transaction whose memory expansion lands exactly on `heap.memory.len()` bytes receives a false `OutOfGas` result. The transaction is marked failed and all gas is burned, diverging from correct EVM semantics where the transaction should succeed. This is an **EVM semantic mismatch**: forward execution produces an incorrect outcome (failed) for a transaction that the EVM specification requires to succeed.

Concretely:
- A contract that carefully pre-computes its gas budget and memory usage to fit within the allocated heap will unexpectedly run out of gas.
- The divergence between ZKsync OS and a reference EVM implementation is observable on-chain (different receipt status, different state root).
- Because the backing buffer size is deterministic and system-controlled, an attacker who knows the heap allocation size can craft a transaction that reliably triggers the false OOG, causing a valid high-value call to fail.

### Likelihood Explanation

The backing memory for the EVM heap is allocated by the system at a fixed size per execution frame. Any transaction whose memory footprint (rounded up to the next 32-byte word) equals exactly that allocation size will hit the bug. Because the allocation size is deterministic and the EVM memory cost formula is public, this boundary is predictable. Contracts that use large memory regions (e.g., ABI-decoding large calldata, keccak over large buffers, or MCOPY of large blobs) are most likely to approach the boundary.

### Recommendation

Change the guard in `SliceVec::resize` from `>=` to `>`:

```rust
// zk_ee/src/memory/slice_vec.rs
pub fn resize(&mut self, new_length: usize, padding: T) -> Result<(), ()> {
-   if new_length >= self.memory.len() {
+   if new_length > self.memory.len() {
        return Err(());
    }
    ...
}
``` [4](#0-3) 

This allows the backing buffer to be fully utilized, matching the intended semantics of a fixed-capacity vector.

### Proof of Concept

1. Deploy a contract whose constructor or a function executes `MSTORE` at offset `N - 32`, where `N` is the exact backing-buffer size of the EVM heap (a system constant).
2. The required `new_heap_size` = `(N - 32 + 32).next_multiple_of(32)` = `N`.
3. `resize_heap_implementation` calls `heap.resize(N, 0)`.
4. `SliceVec::resize` evaluates `N >= heap.memory.len()` → `N >= N` → `true` → returns `Err(())`.
5. `resize_heap_implementation` maps `Err(())` to `ExitCode::EvmError(EvmError::OutOfGas)`.
6. The transaction fails with OOG and all gas is consumed, despite the access being within the EVM memory limit and the caller having paid sufficient gas.

A reference EVM (e.g., revm, geth) would execute the same transaction successfully, demonstrating the divergence. [5](#0-4) [2](#0-1)

### Citations

**File:** zk_ee/src/memory/slice_vec.rs (L77-99)
```rust
    pub fn resize(&mut self, new_length: usize, padding: T) -> Result<(), ()> {
        if new_length >= self.memory.len() {
            return Err(());
        }

        if new_length > self.length {
            for x in &mut self.memory[self.length..new_length] {
                x.write(padding.clone());
            }
        }
        if new_length < self.length {
            unsafe {
                assert_unchecked(self.length <= self.memory.len());
                ptr::drop_in_place(
                    &mut self.memory[new_length..self.length] as *mut [MaybeUninit<T>]
                        as *mut [T],
                );
            }
        }
        self.length = new_length;

        Ok(())
    }
```

**File:** evm_interpreter/src/utils.rs (L72-93)
```rust
    pub(crate) fn resize_heap_implementation<'a>(
        heap: &mut SliceVec<'a, u8>,
        gas: &mut Gas<S>,
        offset: usize,
        len: usize,
    ) -> Result<(), ExitCode> {
        let max_offset = offset.saturating_add(len);
        let new_heap_size = if max_offset > ((u32::MAX - 31) as usize) {
            return Err(ExitCode::EvmError(EvmError::MemoryLimitOOG));
        } else {
            max_offset.next_multiple_of(32)
        };
        let current_heap_size = heap.len();
        if new_heap_size > current_heap_size {
            gas.pay_for_memory_growth(current_heap_size, new_heap_size)?;

            heap.resize(new_heap_size, 0)
                .map_err(|_| ExitCode::EvmError(EvmError::OutOfGas))?;
        }

        Ok(())
    }
```
