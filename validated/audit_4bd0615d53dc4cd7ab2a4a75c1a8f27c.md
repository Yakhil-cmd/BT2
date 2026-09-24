No vulnerability found for this question.

The CVE-2025-66865 describes a crash in BinUtils' C `cp-demangle.c` (C++ symbol demangler) when parsing a crafted PE file. This is unrelated to the Polkadot SDK's Rust/FRAME/XCM codebase.

Searching the repository, the only related matches are to a `rustc-demangle`/demangle dependency reference in `Cargo.lock` and `substrate/client/executor/wasmtime/Cargo.toml` [1](#0-0) , which is a build/runtime dependency used for symbolizing Wasm execution backtraces, not code that parses attacker-supplied PE binaries or C++ mangled symbols through any signed extrinsic, contract call, or XCM entry point. There is no production code in this codebase implementing or exposing `d_print_comp_inner`-style demangling logic reachable by an unprivileged user.

Per the reporting rules, dependency-only references without a real user-facing entry point and without a demonstrated FRAME/XCM analog do not qualify, so no vulnerability analog is supported here.

### Citations

**File:** substrate/client/executor/wasmtime/Cargo.toml (L1-1)
```text
[package]
```
