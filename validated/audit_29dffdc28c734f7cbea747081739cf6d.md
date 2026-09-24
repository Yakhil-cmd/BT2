No vulnerability found for this question.

This CVE describes a heap overflow in the Linux kernel's ASoC SOF audio driver, caused by bounds checks (`bytes_ext_put`/`_bytes_ext_get`) that compared user-supplied lengths against the full allocation size (`max_size`) without subtracting the fixed `sizeof(struct sof_ipc_ctrl_data)` header offset at which the flexible-array payload actually begins.

I searched the Polkadot SDK codebase for the analogous bug class — bounds checks on user-controlled buffer lengths that fail to account for a struct/header offset before the payload — across the memory-boundary-crossing surfaces most likely to reproduce this pattern (wasm executor memory transfer, contracts pallet sandbox memory, and revive/EVM memory handling). All relevant bounds-check implementations found correctly account for offsets:

- `substrate/client/executor/common/src/util.rs` `checked_range` and its callers in `substrate/client/executor/wasmtime/src/util.rs` (`read_memory_into`/`write_memory_from`) validate `offset + len <= memory.len()` directly against the actual buffer, with no separate header region being ignored. [1](#0-0) [2](#0-1) 
- `substrate/frame/contracts/src/wasm/runtime.rs` `read_sandbox_memory_into_buf`/`write_sandbox_memory` use `memory.get(ptr..ptr+len)` directly against the sandbox slice, with no struct-header offset subtraction needed since there's no analogous fixed-header-then-payload layout being bounds-checked incorrectly. [3](#0-2) [4](#0-3) 
- `substrate/frame/revive/src/vm/evm/memory.rs` `resize`/`set_data` and `substrate/frame/revive/src/vm/pvm/env.rs` `return_data_copy` correctly bound-check `offset`/`len` against the actual data length before copying. [5](#0-4) [6](#0-5) 

None of these exhibit the specific defect pattern in the report — a bounds check validating against total allocation size while the actual writable region begins at a fixed offset into that allocation (a C struct with header + flexible array member). This pattern is inherent to the C `struct sof_ipc_ctrl_data` layout in a kernel audio driver and does not have a structurally equivalent construct in the reviewed Rust/FRAME/WASM/EVM memory-handling code, where bounds checks are performed directly against the actual buffer/slice being written rather than against an oversized allocation containing an unaccounted header offset.

### Citations

**File:** substrate/client/executor/common/src/util.rs (L27-30)
```rust
pub fn checked_range(offset: usize, len: usize, max: usize) -> Option<Range<usize>> {
	let end = offset.checked_add(len)?;
	(end <= max).then(|| offset..end)
}
```

**File:** substrate/client/executor/wasmtime/src/util.rs (L30-41)
```rust
pub(crate) fn read_memory_into(
	ctx: impl AsContext<Data = StoreData>,
	address: Pointer<u8>,
	dest: &mut [u8],
) -> Result<()> {
	let memory = ctx.as_context().data().memory().data(&ctx);

	let range = checked_range(address.into(), dest.len(), memory.len())
		.ok_or_else(|| Error::Other("memory read is out of bounds".into()))?;
	dest.copy_from_slice(&memory[range]);
	Ok(())
}
```

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L571-582)
```rust
	pub fn read_sandbox_memory_into_buf(
		&self,
		memory: &[u8],
		ptr: u32,
		buf: &mut [u8],
	) -> Result<(), DispatchError> {
		let ptr = ptr as usize;
		let bound_checked =
			memory.get(ptr..ptr + buf.len()).ok_or_else(|| Error::<E::T>::OutOfBounds)?;
		buf.copy_from_slice(bound_checked);
		Ok(())
	}
```

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L682-693)
```rust
	fn write_sandbox_memory(
		&self,
		memory: &mut [u8],
		ptr: u32,
		buf: &[u8],
	) -> Result<(), DispatchError> {
		let ptr = ptr as usize;
		let bound_checked =
			memory.get_mut(ptr..ptr + buf.len()).ok_or_else(|| Error::<E::T>::OutOfBounds)?;
		bound_checked.copy_from_slice(buf);
		Ok(())
	}
```

**File:** substrate/frame/revive/src/vm/evm/memory.rs (L66-79)
```rust
	pub fn resize(&mut self, offset: usize, len: usize) -> ControlFlow<Halt> {
		let current_len = self.data.len();
		let target_len = revm::interpreter::num_words(offset.saturating_add(len)) * 32;
		if target_len > crate::limits::EVM_MEMORY_BYTES as usize {
			log::debug!(target: crate::LOG_TARGET, "check memory bounds failed: offset={offset} target_len={target_len} current_len={current_len}");
			return ControlFlow::Break(Error::<T>::OutOfGas.into());
		}

		if target_len > current_len {
			self.data.resize(target_len, 0);
		}

		ControlFlow::Continue(())
	}
```

**File:** substrate/frame/revive/src/vm/pvm/env.rs (L857-879)
```rust
	fn return_data_copy(
		&mut self,
		memory: &mut M,
		out_ptr: u32,
		out_len_ptr: u32,
		offset: u32,
	) -> Result<(), TrapReason> {
		let output = mem::take(self.ext.last_frame_output_mut());
		let result = if offset as usize > output.data.len() {
			Err(Error::<E::T>::OutOfBounds.into())
		} else {
			self.write_sandbox_output(
				memory,
				out_ptr,
				out_len_ptr,
				&output.data[offset as usize..],
				false,
				|len| Some(RuntimeCosts::CopyToContract(len)),
			)
		};
		*self.ext.last_frame_output_mut() = output;
		Ok(result?)
	}
```
