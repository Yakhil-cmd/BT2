Audit Report

## Title
Sandbox Process Can Crash Replica via `ftruncate()` on `MAP_SHARED` Heap-Delta File — (`rs/replicated_state/src/page_map/page_allocator/mmap.rs`, `ic-os/components/guestos/selinux/ic-node/ic-node.te`)

## Summary
The SELinux policy grants `write` permission on `ic_canister_mem_t` files to the sandbox domain, which on Linux is sufficient to call `ftruncate()`. The replica maps the same backing files with `MAP_SHARED`, so a compromised sandbox that truncates a received file descriptor causes `SIGBUS` on the replica's next access to any page beyond the new file size, crashing the replica process. DFINITY's own SELinux policy documentation explicitly classifies this as a presently unmitigated security goal violation.

## Finding Description
Three independently verifiable facts combine:

**1. SELinux grants `write` on `ic_canister_mem_t` to the sandbox domain.**
In `ic-os/components/guestos/selinux/ic-node/ic-node.te` line 316:
```
allow ic_canister_sandbox_t ic_canister_mem_t : file { map read write getattr };
```
On Linux, `write` permission on an open file descriptor is sufficient to invoke `ftruncate(fd, 0)`. There is no separate SELinux `truncate` class permission that is denied.

**2. The replica maps heap-delta backing files with `MAP_SHARED`.**
`MmapBasedPageAllocatorCore::new_allocation_area()` in `rs/replicated_state/src/page_map/page_allocator/mmap.rs` (lines 607–616) and `grow_for_deserialization()` (lines 692–701) both use `MapFlags::MAP_SHARED`. Under POSIX, if the underlying file is truncated after a `MAP_SHARED` mapping is established, any access to a page beyond the new file size delivers `SIGBUS` to the accessing process.

**3. No mitigations are in place.**
- No `F_SEAL_SHRINK` / `F_ADD_SEALS` sealing is applied to the `memfd` before it is passed to the sandbox (confirmed by grep: zero matches for `F_SEAL_SHRINK`, `MFD_ALLOW_SEALING` in the relevant Rust sources).
- The existing `SIGBUS` handler in `rs/embedders/src/wasmtime_embedder/signal_handler.rs` only handles `SIGSEGV` on Linux (line 53–57 explicitly routes `SIGBUS` only for macOS); it does not cover `SIGBUS` from truncated `MAP_SHARED` mappings on the production Linux target.
- DFINITY's own documentation at `ic-os/guestos/docs/SELinux-Policy.adoc` lines 327–328 states: *"This interaction cannot presently be prevented by policy, requires some more investigation and/or other mechanism to be put into place."*

**Exploit flow:**
1. Attacker achieves a Wasm sandbox escape (precondition).
2. The sandbox process already holds a writable fd for an `ic_canister_mem_t`-labeled file, passed via `socket_read_messages` / `SCM_RIGHTS` IPC in `rs/canister_sandbox/src/transport.rs`.
3. Sandbox calls `ftruncate(received_fd, 0)`.
4. Replica's next access to any page in its `MAP_SHARED` mapping of that file receives `SIGBUS`.
5. `SIGBUS` is unhandled on Linux in the replica; the replica process terminates.

## Impact Explanation
The concrete impact is a crash of a single replica node. This matches the allowed Medium bounty impact: *"One-time crash of a single replica on an application subnet, limited subnet availability impact."* The subnet continues with remaining replicas but loses one node's participation, degrading fault tolerance. Repeated exploitation across multiple canister sandboxes on the same node (each holding its own fd) could amplify the effect, but the primary proven impact is a single-node crash.

## Likelihood Explanation
The precondition is a Wasm sandbox escape, which is non-trivial but is an acknowledged and actively researched attack surface for canister execution environments. Once a sandbox escape is achieved, the `ftruncate` path is trivial, deterministic, requires no additional privilege escalation, and is immediately available because the fd is already in the sandbox's possession. The DFINITY team has confirmed the mechanism in their own documentation and has not deployed a fix.

## Recommendation
The DFINITY documentation lists several remedies (`ic-os/guestos/docs/SELinux-Policy.adoc` lines 330–336). The most immediately deployable:
- **`memfd` sealing**: Call `fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK)` on the backing `memfd` before passing it to the sandbox. This prevents `ftruncate` from reducing the file size without requiring architectural changes for the grow-only case.
- **`MAP_PRIVATE` for replica-side reads**: Where the replica only reads page delta contents (e.g., at checkpoint time), use `MAP_PRIVATE` instead of `MAP_SHARED`. Already-faulted pages in a `MAP_PRIVATE` mapping are not affected by subsequent truncation of the underlying file.
- **Architectural change**: Remove the requirement for the replica to keep heap-delta files `mmap`-ed concurrently with sandbox access, as noted in the documentation.

## Proof of Concept
```c
// Replica analog
int fd = memfd_create("heap_delta", MFD_CLOEXEC);
ftruncate(fd, 4096);
void *map = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
memset(map, 0xAA, 4096);

// Pass fd to sandbox via SCM_RIGHTS (matching rs/canister_sandbox/src/transport.rs IPC path)
// ... sendmsg with SCM_RIGHTS ...

// Sandbox analog (post-escape): truncate to zero
ftruncate(received_fd, 0);

// Replica: next access to the mapping → SIGBUS → process terminates
char val = ((char*)map)[0];  // SIGBUS here
```
This is directly reproducible with a `memfd_create` + `fork` + `SCM_RIGHTS` harness on any Linux system, matching the production IPC path. No mainnet access is required.