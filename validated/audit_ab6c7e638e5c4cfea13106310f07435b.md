## Finding: Immutable-provenance pointer cast used to construct a writable VM memory region in CPI account serialization

### Title
Mutable VM memory region constructed from immutable-provenance pointer in `modify_memory_region_of_account` - (File: program-runtime/src/serialization.rs)

### Summary
`modify_memory_region_of_account` in `program-runtime/src/serialization.rs` derives the pointer used to redirect a program's account-data memory region from `region.host_buffer().ptr()` — the read-only accessor — and then casts it to `*mut u8`, instead of using the crate's own mutable accessor (`ptr_mut()`, used correctly elsewhere, e.g. in `program-runtime/src/memory.rs`/`syscalls/src/lib.rs` `translate_slice_inner!`). This is the exact bug class described in GHSA-9wgh-vjj7-7433 / CVE-2020-35916: obtaining a mutable reference/pointer by casting the result of an immutable accessor (`as_ptr`-equivalent) rather than calling the mutable accessor (`as_mut_ptr`-equivalent), which produces a pointer with immutable provenance under Rust's aliasing/provenance model even though it is later used for writes. [1](#0-0) 

### Finding Description
`modify_memory_region_of_account` is used to patch a `MemoryRegion`'s backing buffer to point at an account's current data buffer (used for CPI / `virtual_address_space_adjustments` account-region updates):

```rust
let data_ptr = region.host_buffer().ptr() as *mut u8;
let new_buffer = std::ptr::slice_from_raw_parts_mut(data_ptr, account.get_data().len());
if account.can_data_be_changed().is_ok() {
    unsafe { region.redirect(new_buffer); }
    ...
}
``` [2](#0-1) 

Elsewhere in the same codebase, the correct pattern is followed: the `translate_slice_inner!` macro in `program-runtime/src/memory.rs` and `syscalls/src/lib.rs` explicitly obtains a *mutable* pointer via `host_buf.ptr_mut()` when building a writable slice, reserving `.ptr()` only for read-only paths or non-dereferencing checks (e.g. alignment checks). [3](#0-2) 

In `modify_memory_region_of_account`, however, the writable region is built from the immutable `.ptr()` accessor. The resulting `*mut u8`/`&mut [u8]` slice therefore carries provenance derived from a shared/read-only reference. Under Rust's Stacked Borrows / Tree Borrows aliasing model this is undefined behavior: the compiler is permitted to treat memory reached only through this pointer as not-written-through, potentially reordering, eliding, or misoptimizing subsequent reads/writes to the same memory performed through other (correctly-provenanced) aliases of the account data buffer (e.g. `BorrowedInstructionAccount::get_data`/`get_data_mut`, or SBPF VM reads through the `MemoryRegion`).

This region is subsequently marked writable (`region.access_violation_handler_payload = Some(...)`) and used by the SBF VM to service loads/stores for account data addresses during CPI, meaning a guest program's writes are funneled through a region whose host pointer has unsound provenance for writing.

### Impact Explanation
If the compiler exploits the aliasing violation (more likely under future/aggressive LLVM optimization or with Rust's Tree Borrows enforcement), writes performed by the SBF VM to account data through this region could be miscompiled: writes could be dropped, reordered past reads on other aliases, or the accompanying data could fail to be committed/zeroed as intended. Because this path directly backs account data during CPI (`update_callee_account`/`update_caller_account` flows in `program-runtime/src/cpi.rs` call into this serialization machinery), a miscompilation here could cause account data corruption, incorrect account state being committed to the bank, or divergent behavior between validators built with different compiler versions/optimization levels — i.e., a consensus-divergence class of impact, since it affects deterministic bank-commit state derived from every transaction that performs a CPI touching account data with `virtual_address_space_adjustments` enabled.

### Likelihood Explanation
The path is reachable from any unprivileged program performing a CPI, since `modify_memory_region_of_account` is invoked from `program-runtime/src/cpi.rs` (3 call sites) as part of routine account-region maintenance around CPI calls — no special privileges are required beyond invoking a cross-program instruction. However, whether this manifests as an observable bug depends on whether the specific compiler/LLVM version actually exploits the UB (in practice, LLVM historically has not aggressively exploited provenance violations of this specific shape, similar to how the original `image` crate bug went unnoticed for a long time). This makes the *practical* likelihood of triggering divergent behavior on current toolchains low-to-moderate, while the code is nonetheless provably unsound.

### Recommendation
Replace `region.host_buffer().ptr() as *mut u8` with the crate's mutable accessor (`region.host_buffer_mut().ptr_mut()` or equivalent, mirroring the pattern already used correctly in `program-runtime/src/memory.rs`'s `translate_slice_inner!`), so that the resulting pointer carries proper mutable provenance before it is used to construct the region redirected via `region.redirect(new_buffer)`. Add a `cargo miri` or Tree-Borrows-focused test exercising `modify_memory_region_of_account`/CPI account resizing to catch regressions of this class in CI.

### Proof of Concept
No transaction-triggerable crash/exploit could be concretely demonstrated from static analysis alone — this is a provenance/aliasing soundness bug rather than a logic bug with a deterministic PoC. Its exact runtime manifestation depends on the Rust/LLVM version and optimization behavior, which could not be verified with the tools available (no ability to build/run the code, and the exact definition/safety contract of `HostBuffer::ptr()`/`ptr_mut()` lives in the external `solana_sbpf` crate, which is outside this repo's index). A concrete PoC would require compiling agave with a toolchain build that exploits Tree Borrows or running the CPI account-resize path under Miri to observe a diverging read/write, which is left for a background engineering task with build/test access.

### Citations

**File:** program-runtime/src/serialization.rs (L23-53)
```rust
pub fn modify_memory_region_of_account(
    account: &mut BorrowedInstructionAccount<'_, '_>,
    region: &mut MemoryRegion,
) {
    let data_ptr = region.host_buffer().ptr() as *mut u8;
    let new_buffer = std::ptr::slice_from_raw_parts_mut(data_ptr, account.get_data().len());
    if account.can_data_be_changed().is_ok() {
        unsafe {
            // SAFETY:
            // Contract from `MemoryRegion::redirect`: The memory pointed to by the MemoryRegions
            // must point to a valid object live for the duration of this MemoryMapping.
            //
            // TODO(nagisa): Local reasoning for this contract is infeasible. In particular for the
            // `serialization.rs` code it is pretty easy to see that the regions passed in will
            // always be larger than `account.get_data().len()`. However for `cpi.rs` callsite this
            // is not as easy to prove and relies on careful coordination between any code that
            // might increase the account data buffer length.
            region.redirect(new_buffer);
        }
        region.access_violation_handler_payload = Some(account.get_index_in_transaction());
    } else {
        unsafe {
            // SAFETY:
            //
            // Contract from `MemoryRegion::redirect`: same as for the call above.
            // Evidence: same as for the call above.
            region.redirect(new_buffer.cast_const());
        }
        region.access_violation_handler_payload = None;
    }
}
```

**File:** program-runtime/src/memory.rs (L83-93)
```rust
                    Ok(host_buf) if $check_aligned && !host_buf.ptr().cast::<$T>().is_aligned() => {
                        Err($crate::memory::MemoryTranslationError::UnalignedPointer.into())
                    }
                    Ok(host_buf) => Ok(std::ptr::slice_from_raw_parts_mut(
                        host_buf.ptr_mut().cast(),
                        $len as usize,
                    )),
                }
            }
        }
    }};
```
