No vulnerability found for this question.

I searched for a Polkadot SDK analog to the libtpms bug (an unchecked skip/block size that drives a signed counter negative, which is bypassed by an unsafe signed→unsigned cast, causing a heap OOB read past the buffer holding the untrusted blob). I examined the closest candidate decode paths:

- SCALE `codec::Input` implementations, e.g. `StorageInput::read`/`remaining_len` in `substrate/frame/support/src/storage/stream_iter.rs` [1](#0-0) , which validate buffer bounds with `saturating_sub`/explicit length checks that return `Err(...)` rather than allowing negative-then-unsigned-cast bypasses.
- Trie node header size decoding (`decode_size`) in `substrate/primitives/trie/src/node_header.rs` [2](#0-1) , which reads via `codec::Input::read_byte()` that errors on insufficient input instead of reading out of bounds.
- Contracts sandbox-memory readers `read_sandbox_memory`/`read_sandbox_memory_as_unbounded` in `substrate/frame/contracts/src/wasm/runtime.rs` [3](#0-2) , which use `memory.get(ptr..ptr+len)` (safe slice indexing returning `None`/error) rather than raw pointer arithmetic with an unchecked signed size.
- The wasm allocator's `heap_range` bounds check in `substrate/client/allocator/src/freeing_bump.rs` [4](#0-3) , which uses `checked_add` and an explicit `<=` comparison, not a signed subtraction.

In every reachable decode/read path I could find (SCALE codec inputs, trie/MMR/merkle proof decoding, contracts/revive sandbox memory access, wasm allocator), bounds are enforced either through safe Rust slice indexing (`get`, `get_mut`) that returns `None`/an error instead of performing an out-of-bounds memory access, or through `checked_*`/`saturating_*` arithmetic that cannot produce the negative-counter-then-unsigned-cast bypass described in the libtpms report. Rust's memory-safety guarantees around slice indexing prevent this specific bug class (a signed-to-unsigned cast silently reinterpreting a negative remaining-size as a huge unsigned value to read past a buffer) from manifesting as an actual heap OOB read; a logic error of this shape in these paths would at worst produce a `Result::Err` or a panic, not memory-unsafe out-of-bounds reads. I found no user-reachable entry point (extrinsic, XCM message, contract call) where such an unchecked size-skip bypasses a bounds check and performs an out-of-bounds heap read.

### Citations

**File:** substrate/frame/support/src/storage/stream_iter.rs (L363-391)
```rust
impl codec::Input for StorageInput {
	fn remaining_len(&mut self) -> Result<Option<usize>, codec::Error> {
		Ok(Some(self.total_length.saturating_sub(
			self.offset.saturating_sub((self.buffer.len() - self.buffer_pos) as u32),
		) as usize))
	}

	fn read(&mut self, into: &mut [u8]) -> Result<(), codec::Error> {
		// If there is still data left to be read from the state.
		if self.offset < self.total_length {
			if into.len() > self.buffer.capacity() {
				return self.read_big_item(into);
			} else if self.buffer_pos + into.len() > self.buffer.len() {
				self.fill_buffer()?;
			}
		}

		// Guard against `fill_buffer` not reading enough data or just not having enough data
		// anymore.
		if into.len() + self.buffer_pos > self.buffer.len() {
			return Err("Not enough data to fill the buffer".into());
		}

		let end = self.buffer_pos + into.len();
		into.copy_from_slice(&self.buffer[self.buffer_pos..end]);
		self.buffer_pos = end;

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

**File:** substrate/client/allocator/src/freeing_bump.rs (L620-628)
```rust
fn heap_range(offset: u32, length: u32, heap_len: usize) -> Option<Range<usize>> {
	let start = offset as usize;
	let end = offset.checked_add(length)? as usize;
	if end <= heap_len {
		Some(start..end)
	} else {
		None
	}
}
```
