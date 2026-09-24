No vulnerability found for this question.

Investigation summary: The CVE-2021-32272 concerns a heap-buffer-overflow (out-of-bounds memory write enabling code execution) in C code (`faad2`'s `mp4read.c`) due to missing bounds checks on attacker-controlled length fields. Searching the Polkadot SDK for an analogous pattern — a genuine, reachable user entry point that decodes attacker-controlled length/offset fields without bounds checking, leading to memory corruption — did not surface a valid analog:

- `substrate/frame/revive/uapi/src/precompiles/utils.rs` `decode_bytes` (lines 138-152) reads offset/length words from `input` and slices `input[32+offset..32+offset+bytes_len]` without bounds checks [1](#0-0) , but this function is only referenced from the test fixture `substrate/frame/revive/fixtures/sol_utils.rs`, not from any production precompile or dispatchable path, so it is not reachable by an unprivileged attacker and falls under excluded test/fixture-only findings.
- The actual production precompile `Modexp::call` uses a bounds-safe `read_input` helper that clamps reads to the source length, explicitly avoiding out-of-bounds access [2](#0-1) .
- Contract-memory access in pallet-contracts (`read_sandbox_memory`, `read_sandbox_memory_as_unbounded`) explicitly bounds-checks pointer+length against sandbox memory size before copying, returning `Error::OutOfBounds` on failure [3](#0-2) .
- Wasmtime host/runtime memory access (`read_memory_into`, `write_memory_from`, `extract_output_data`) similarly perform `checked_range` bounds validation before any read/write into WASM linear memory [4](#0-3) [5](#0-4) .
- Extrinsic length-prefix decoding (`UncheckedExtrinsic::decode`/`decode_with_len`) uses SCALE's `Compact<u32>` length together with `DecodeWithMemLimit`/`CountedInput` to enforce that decoded byte counts match the declared length and stay within `MAX_CALL_SIZE`, rejecting mismatches rather than trusting an attacker-supplied length for a raw memory copy [6](#0-5) [7](#0-6) .

More fundamentally, Rust's memory-safety model means that even an unchecked slice index (as in the unused `decode_bytes`) would trigger a panic/abort rather than a silent heap-buffer-overflow enabling arbitrary code execution as in the C `faad2` codec — there is no unsafe raw pointer arithmetic over attacker-controlled offsets in any reachable, non-test production path found. No genuine, reachable analog to the CVE's violated invariant (missing bound check on attacker-controlled length before a raw memory copy leading to code execution) was found in scope.

### Citations

**File:** substrate/frame/revive/uapi/src/precompiles/utils.rs (L138-152)
```rust
pub fn decode_bytes(input: &[u8], out: &mut [u8]) -> usize {
	let mut buf = [0u8; 4];
	buf[..].copy_from_slice(&input[28..32]);
	let offset = u32::from_be_bytes(buf) as usize;

	let mut buf = [0u8; 4];
	buf[..].copy_from_slice(&input[60..64]);
	let bytes_len = u32::from_be_bytes(buf) as usize;

	// we start decoding at the start of the payload.
	// the payload starts at the `len` word here:
	// `bytes = offset (32 bytes) | len (32 bytes) | data`
	out[..bytes_len].copy_from_slice(&input[32 + offset..32 + offset + bytes_len]);
	bytes_len
}
```

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L571-628)
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

	/// Reads and decodes a type with a size fixed at compile time from contract memory.
	///
	/// # Note
	///
	/// The weight of reading a fixed value is included in the overall weight of any
	/// contract callable function.
	pub fn read_sandbox_memory_as<D: Decode + MaxEncodedLen>(
		&self,
		memory: &[u8],
		ptr: u32,
	) -> Result<D, DispatchError> {
		let ptr = ptr as usize;
		let mut bound_checked = memory.get(ptr..).ok_or_else(|| Error::<E::T>::OutOfBounds)?;

		let decoded = D::decode_with_depth_limit(MAX_DECODE_NESTING, &mut bound_checked)
			.map_err(|_| DispatchError::from(Error::<E::T>::DecodingFailed))?;
		Ok(decoded)
	}

	/// Read designated chunk from the sandbox memory and attempt to decode into the specified type.
	///
	/// Returns `Err` if one of the following conditions occurs:
	///
	/// - requested buffer is not within the bounds of the sandbox memory.
	/// - the buffer contents cannot be decoded as the required type.
	///
	/// # Note
	///
	/// There must be an extra benchmark for determining the influence of `len` with
	/// regard to the overall weight.
	pub fn read_sandbox_memory_as_unbounded<D: Decode>(
		&self,
		memory: &[u8],
		ptr: u32,
		len: u32,
	) -> Result<D, DispatchError> {
		let ptr = ptr as usize;
		let mut bound_checked =
			memory.get(ptr..ptr + len as usize).ok_or_else(|| Error::<E::T>::OutOfBounds)?;

		let decoded = D::decode_all_with_depth_limit(MAX_DECODE_NESTING, &mut bound_checked)
			.map_err(|_| DispatchError::from(Error::<E::T>::DecodingFailed))?;

		Ok(decoded)
	}
```

**File:** substrate/client/executor/wasmtime/src/util.rs (L29-58)
```rust
/// Returns an error if the read would go out of the memory bounds.
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

/// Write data to the instance memory from a slice.
///
/// Returns an error if the write would go out of the memory bounds.
pub(crate) fn write_memory_from(
	mut ctx: impl AsContextMut<Data = StoreData>,
	address: Pointer<u8>,
	data: &[u8],
) -> Result<()> {
	let memory = ctx.as_context().data().memory();
	let memory = memory.data_mut(&mut ctx);

	let range = checked_range(address.into(), data.len(), memory.len())
		.ok_or_else(|| Error::Other("memory write is out of bounds".into()))?;
	memory[range].copy_from_slice(data);
	Ok(())
}
```

**File:** substrate/client/executor/wasmtime/src/runtime.rs (L727-747)
```rust
fn extract_output_data(
	instance: &InstanceWrapper,
	output_ptr: u32,
	output_len: u32,
) -> Result<Vec<u8>> {
	let ctx = instance.store();

	// Do a length check before allocating. The returned output should not be bigger than the
	// available WASM memory. Otherwise, a malicious parachain can trigger a large allocation,
	// potentially causing memory exhaustion.
	//
	// Get the size of the WASM memory in bytes.
	let memory_size = ctx.as_context().data().memory().data_size(ctx);
	if checked_range(output_ptr as usize, output_len as usize, memory_size).is_none() {
		Err(Error::OutputExceedsBounds)?
	}
	let mut output = vec![0; output_len as usize];

	util::read_memory_into(ctx, Pointer::new(output_ptr), &mut output)?;
	Ok(output)
}
```

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L508-559)
```rust
	fn decode_with_len<I: Input>(input: &mut I, len: usize) -> Result<Self, codec::Error>
	where
		Preamble<Address, Signature, ExtensionV0, ExtensionOtherVersions>: DecodeWithMemTracking,
		Call: DecodeWithMemTracking,
	{
		let mut input = CountedInput::new(input);

		// Decode the preamble using the same memory limit as we will use for the `call`.
		// The preamble is not that big, but we play it safe.
		let preamble =
			DecodeWithMemLimit::decode_with_mem_limit(&mut input, MAX_CALL_SIZE.saturating_add(1))?;

		struct CloneBytes<'a, I>(&'a mut I, Vec<u8>);
		impl<I: Input> Input for CloneBytes<'_, I> {
			fn remaining_len(&mut self) -> Result<Option<usize>, codec::Error> {
				self.0.remaining_len()
			}

			fn read(&mut self, into: &mut [u8]) -> Result<(), codec::Error> {
				self.0.read(into)?;

				self.1.extend_from_slice(into);
				Ok(())
			}

			fn descend_ref(&mut self) -> Result<(), codec::Error> {
				self.0.descend_ref()
			}

			fn ascend_ref(&mut self) {
				self.0.ascend_ref();
			}

			fn on_before_alloc_mem(&mut self, size: usize) -> Result<(), codec::Error> {
				self.0.on_before_alloc_mem(size)
			}
		}

		let mut clone_bytes = CloneBytes(&mut input, Vec::with_capacity(len));

		// Adds 1 byte to the `MAX_CALL_SIZE` as the decoding fails exactly at the given value and
		// the maximum should be allowed to fit in.
		let function =
			Call::decode_with_mem_limit(&mut clone_bytes, MAX_CALL_SIZE.saturating_add(1))?;

		let encoded_call = Some(clone_bytes.1);

		if input.count() != len as u64 {
			return Err("Invalid length prefix".into());
		}

		Ok(Self { preamble, function, encoded_call, encoded_len: Some(len) })
```

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L771-778)
```rust
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		// This is a little more complicated than usual since the binary format must be compatible
		// with SCALE's generic `Vec<u8>` type. Basically this just means accepting that there
		// will be a prefix of vector length.
		let expected_length: Compact<u32> = Decode::decode(input)?;

		Self::decode_with_len(input, expected_length.0 as usize)
	}
```
