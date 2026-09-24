No vulnerability found for this question.

The reported issue (ALPINE-CVE-2026-0799) is a memory-safety bug in the C library `libpcap`'s BPF interpreter, where an unchecked scratch-memory register index in BPF load/store instructions allows out-of-bounds reads/writes. This is a packet-capture/tcpdump-related dependency, and my search found no evidence that `libpcap` is a dependency of this repository at all — it does not appear in `Cargo.toml` or `Cargo.lock`.

I looked for a plausible Polkadot SDK analog (interpreters with register/index-based memory access that lack bounds checks), examining:
- The Substrate Wasm executor's memory-access utilities (`checked_range`, `MemoryTransfer`) which do perform explicit bounds checks. [1](#0-0) 
- `pallet-revive`'s PolkaVM (PVM) interpreter memory/register interface, which performs explicit `get`/`get_mut` bounds checks on every memory access rather than trusting a raw register index. [2](#0-1) 
- `pallet-contracts`'s Wasm memory-access validation, which similarly rejects out-of-bounds pointers before use. [3](#0-2) 

None of these constitute a BPF-style scratch-register-indexing vulnerability, and there is no evidence `libpcap` or any BPF filter-program interpreter is compiled into, linked by, or reachable from any Polkadot SDK production code path (runtime, node, or client). Forcing an analogy onto the PVM/Wasm interpreters would not be a legitimate match since those interpreters validate memory bounds on every access rather than trusting an unchecked register index, and there is no user-facing extrinsic, XCM, or contract entry point that lets an attacker supply raw BPF instructions to any interpreter in this codebase.

### Citations

**File:** substrate/client/executor/common/src/util.rs (L26-30)
```rust
/// Returns None if the end of the range would exceed some maximum offset.
pub fn checked_range(offset: usize, len: usize, max: usize) -> Option<Range<usize>> {
	let end = offset.checked_add(len)?;
	(end <= max).then(|| offset..end)
}
```

**File:** substrate/frame/revive/src/vm/pvm.rs (L150-192)
```rust
impl<T: Config> Memory<T> for [u8] {
	fn read_into_buf(&mut self, ptr: u32, buf: &mut [u8]) -> Result<(), DispatchError> {
		let ptr = ptr as usize;
		let bound_checked =
			self.get(ptr..ptr + buf.len()).ok_or_else(|| Error::<T>::OutOfBounds)?;
		buf.copy_from_slice(bound_checked);
		Ok(())
	}

	fn write(&mut self, ptr: u32, buf: &[u8]) -> Result<(), DispatchError> {
		let ptr = ptr as usize;
		let bound_checked =
			self.get_mut(ptr..ptr + buf.len()).ok_or_else(|| Error::<T>::OutOfBounds)?;
		bound_checked.copy_from_slice(buf);
		Ok(())
	}

	fn zero(&mut self, ptr: u32, len: u32) -> Result<(), DispatchError> {
		<[u8] as Memory<T>>::write(self, ptr, &vec![0; len as usize])
	}

	fn reset_interpreter_cache(&mut self) {}
}

impl<T: Config> Memory<T> for polkavm::RawInstance {
	fn read_into_buf(&mut self, ptr: u32, buf: &mut [u8]) -> Result<(), DispatchError> {
		self.read_memory_into(ptr, buf)
			.map(|_| ())
			.map_err(|_| Error::<T>::OutOfBounds.into())
	}

	fn write(&mut self, ptr: u32, buf: &[u8]) -> Result<(), DispatchError> {
		self.write_memory(ptr, buf).map_err(|_| Error::<T>::OutOfBounds.into())
	}

	fn zero(&mut self, ptr: u32, len: u32) -> Result<(), DispatchError> {
		self.zero_memory(ptr, len).map_err(|_| Error::<T>::OutOfBounds.into())
	}

	fn reset_interpreter_cache(&mut self) {
		self.reset_interpreter_cache();
	}
}
```

**File:** substrate/frame/contracts/src/wasm/mod.rs (L2582-2593)
```rust
	#[test]
	fn contract_out_of_bounds_access() {
		let mut mock_ext = MockExt::default();
		let result = execute(CODE_OUT_OF_BOUNDS_ACCESS, vec![], &mut mock_ext);

		assert_eq!(
			result,
			Err(ExecError {
				error: Error::<Test>::DecodingFailed.into(),
				origin: ErrorOrigin::Caller,
			})
		);
```
