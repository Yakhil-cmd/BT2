Audit Report

## Title
Unbounded `data.reserve(size)` in `FrameDecoder::decode` Allows Compromised Sandbox to OOM-Abort the Replica — (`rs/canister_sandbox/src/frame_decoder.rs`)

## Summary
`FrameDecoder::decode` reads an attacker-controlled 8-byte big-endian integer from the IPC socket and passes it directly to `BytesMut::reserve` with no upper-bound validation. A compromised sandbox process can write `[0xFF; 8]` to the socket, causing the replica's `CanisterSandboxIPC` thread to call `data.reserve(usize::MAX)`, which triggers the Rust allocator's `handle_alloc_error` and aborts the entire replica process. This crashes the replica, halting the subnet and causing loss of liveness for all canisters on it.

## Finding Description
In `rs/canister_sandbox/src/frame_decoder.rs`, the `FrameDecoderState::Length(size)` branch casts the raw `u64` to `usize` and immediately calls `data.reserve(size)` with no validation:

```rust
FrameDecoderState::Length(size) => {
    let size: usize = *size as usize;
    if data.len() < size {
        data.reserve(size);   // ← no upper-bound check
        return None;
    }
``` [1](#0-0) 

A search across the entire `rs/canister_sandbox/` tree confirms there is no `MAX_FRAME_SIZE`, `max_message_size`, or any equivalent constant or guard anywhere in the codebase. The only size-related constants in `transport.rs` are `INITIAL_BUFFER_CAPACITY` (65536) and `MIN_READ_BUFFER_CAPACITY` (16384), neither of which constrains the frame size parsed by the decoder. [2](#0-1) 

The replica spawns one `CanisterSandboxIPC` thread per sandbox process. That thread runs `socket_read_messages`, which loops calling `decoder.decode(&mut buf)`: [3](#0-2) [4](#0-3) 

The socket is a `UnixStream::pair()` whose controller-side end is held by the replica and whose sandbox-side end is passed to the sandbox process: [5](#0-4) 

The SELinux policy explicitly grants `ic_canister_sandbox_t` write access to `ic_replica_t unix_stream_socket`, confirming there is no OS-level barrier preventing a compromised sandbox from writing arbitrary bytes to the socket.

## Impact Explanation
`BytesMut::reserve(usize::MAX)` attempts a heap allocation of `usize::MAX` bytes. The Rust global allocator cannot satisfy this; it calls `handle_alloc_error`, which **aborts** (not panics) the calling process. Because `socket_read_messages` runs in a thread inside the replica process, the abort kills the entire replica process — not just the thread. This crashes the replica, halting the subnet and causing loss of liveness for every canister on it.

This matches the **High ($2,000–$10,000)** impact class: *"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."*

## Likelihood Explanation
The precondition is a Wasm-level sandbox escape (e.g., a memory-safety bug in wasmtime or a JIT miscompilation granting native code execution inside the sandbox process). This is non-trivial but realistic:

- The IC security model explicitly treats the sandbox as an untrusted process. The IPC socket is a **permitted channel**, so the only protection is the correctness of the frame decoder itself — which has none here.
- Wasmtime JIT bugs are a known, recurring vulnerability class. The IC runs Wasm from arbitrary canisters, making this a realistic second-stage exploit.
- Once a sandbox escape is achieved, writing 8 bytes to an already-open fd requires no further privilege escalation.
- The abort is deterministic and repeatable: any sandbox process can trigger it independently.

## Recommendation
Add a maximum frame size constant and reject frames that exceed it before calling `reserve`:

```rust
const MAX_FRAME_SIZE: usize = 256 * 1024 * 1024; // e.g. 256 MiB

FrameDecoderState::Length(size) => {
    let size: usize = *size as usize;
    if size > MAX_FRAME_SIZE {
        return None; // or propagate an error / close the connection
    }
    if data.len() < size {
        data.reserve(size);
        return None;
    }
    ...
}
```

The check must be inserted before the `data.reserve(size)` call at line 47 of `rs/canister_sandbox/src/frame_decoder.rs`. [6](#0-5) 

## Proof of Concept

```rust
#[test]
fn fuzz_frame_decoder_giant_length() {
    use bytes::BytesMut;
    use crate::frame_decoder::FrameDecoder;

    // Simulate sandbox writing 0xFFFFFFFFFFFFFFFF as the 8-byte length prefix.
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    let mut decoder = FrameDecoder::<Vec<u8>>::new();
    // Without a bounds check this calls data.reserve(usize::MAX) and aborts.
    let result = decoder.decode(&mut buf);
    assert!(result.is_none(), "should return None, not abort");
}
```

Call sequence:
1. Compromised sandbox writes `[0xFF; 8]` to the inherited fd 3 socket.
2. Replica's `CanisterSandboxIPC` thread receives the bytes into `buf` via `receive_message`.
3. `decoder.decode(&mut buf)` transitions to `FrameDecoderState::Length(0xFFFFFFFFFFFFFFFF)`.
4. `data.reserve(usize::MAX)` is called — allocator aborts the replica process.
5. Subnet halts; all canisters lose liveness.

### Citations

**File:** rs/canister_sandbox/src/frame_decoder.rs (L44-58)
```rust
                FrameDecoderState::Length(size) => {
                    let size: usize = *size as usize;
                    if data.len() < size {
                        data.reserve(size);
                        return None;
                    } else {
                        let frame = data.split_to(size);
                        self.state = FrameDecoderState::NoLength;
                        let value = bincode::deserialize(&frame).unwrap();
                        return Some(value);
                    }
                }
            }
        }
    }
```

**File:** rs/canister_sandbox/src/transport.rs (L22-25)
```rust
// The initial capacity of buffers for sending and receiving data bytes.
const INITIAL_BUFFER_CAPACITY: usize = 65536;
// The minimum buffer capacity for reading in `recv_msg()`.
const MIN_READ_BUFFER_CAPACITY: usize = 16384;
```

**File:** rs/canister_sandbox/src/transport.rs (L442-447)
```rust
    let mut decoder = FrameDecoder::<Message>::new();
    let mut buf = BytesMut::with_capacity(INITIAL_BUFFER_CAPACITY);
    let mut fds = Vec::<RawFd>::new();
    let mut reader = SocketReaderWithTimeout::new(socket);
    loop {
        while let Some(mut frame) = decoder.decode(&mut buf) {
```

**File:** rs/canister_sandbox/src/replica_controller/launch_as_process.rs (L90-97)
```rust
    let (sock_controller, sock_sandbox) = std::os::unix::net::UnixStream::pair()?;
    let request = LaunchSandboxRequest {
        sandbox_exec_path: exec_path.to_string(),
        argv: argv.to_vec(),
        canister_id,
        socket: sock_sandbox.as_raw_fd(),
    };
    let LaunchSandboxReply { pid } = launcher.launch_sandbox(request).sync()?;
```

**File:** rs/canister_sandbox/src/replica_controller/launch_as_process.rs (L115-131)
```rust
    let thread_handle = std::thread::Builder::new()
        .name("CanisterSandboxIPC".to_string())
        .spawn(move || {
            let demux = transport::Demux::<_, _, protocol::transport::SandboxToController>::new(
                Arc::new(rpc::ServerStub::new(
                    Arc::clone(&controller_service) as Arc<_>,
                    out.make_sink::<protocol::ctlsvc::Reply>(),
                )),
                reply_handler.clone(),
            );
            transport::socket_read_messages::<_, _>(
                move |message| {
                    demux.handle(message);
                },
                socket,
                SocketReaderConfig::default(),
            );
```
