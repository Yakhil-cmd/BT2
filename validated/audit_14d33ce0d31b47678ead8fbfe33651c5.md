No vulnerability found for this question.

I investigated the codebase for a genuine analog of the GIMP `read_RLE_channel()` bug class — an attacker-controlled length value producing an integer overflow that leads to an undersized heap allocation, followed by per-element writes that overflow that allocation. Specifically I checked:

- SCALE decoding paths for `UncheckedExtrinsic` (`substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs`), where length-prefixed decoding uses `CountedInput`/`DecodeWithMemLimit` and validates the actual consumed length against the declared length rather than trusting an attacker-supplied size for a raw allocation followed by unchecked writes. [1](#0-0) 
- Host/runtime memory marshalling (`substrate/client/executor/wasmtime/src/runtime.rs`, `substrate/primitives/runtime-interface/src/pass_by.rs`), which explicitly perform bounds/length checks before allocating buffers derived from untrusted lengths. [2](#0-1) 
- Contracts/revive sandbox memory writes, which use `memory.get_mut(ptr..ptr+len)` bounds-checked slicing rather than raw pointer writes into a pre-sized buffer. [3](#0-2) 
- Trie node header size decoding and the compressed-blob "bomb limit" decompression path, both of which bound attacker-controlled sizes before use. [4](#0-3) [5](#0-4) 

None of these exhibit the GIMP pattern (attacker-controlled row/element count multiplied without overflow checking to size a heap allocation, followed by unchecked per-row writes past that allocation) reachable through a real unprivileged entry point (signed extrinsic, XCM message, or contract call). Rust's SCALE codec and the FRAME/XCM decoding paths generally read into safely-growable `Vec`s via `extend_from_slice`/`read()` with explicit bounds and remaining-length checks, rather than pre-computing a fixed-size allocation from an overflowable multiplication and then performing raw indexed writes.

### Citations

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

**File:** substrate/client/executor/wasmtime/src/runtime.rs (L727-746)
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

**File:** substrate/primitives/trie/src/node_header.rs (L158-177)
```rust
/// Decode size only from stream input and header byte.
fn decode_size(
	first: u8,
	input: &mut impl Input,
	prefix_mask: usize,
) -> Result<usize, codec::Error> {
	let max_value = 255u8 >> prefix_mask;
	let mut result = (first & max_value) as usize;
	if result < max_value as usize {
		return Ok(result);
	}
	result -= 1;
	loop {
		let n = input.read_byte()? as usize;
		if n < 255 {
			return Ok(result + n + 1);
		}
		result += 255;
	}
}
```

**File:** substrate/primitives/maybe-compressed-blob/src/lib.rs (L50-65)
```rust
fn read_from_decoder(
	decoder: impl Read,
	blob_len: usize,
	bomb_limit: usize,
) -> Result<Vec<u8>, Error> {
	let mut decoder = decoder.take((bomb_limit + 1) as u64);

	let mut buf = Vec::with_capacity(blob_len);
	decoder.read_to_end(&mut buf).map_err(|_| Error::Invalid)?;

	if buf.len() <= bomb_limit {
		Ok(buf)
	} else {
		Err(Error::PossibleBomb)
	}
}
```
