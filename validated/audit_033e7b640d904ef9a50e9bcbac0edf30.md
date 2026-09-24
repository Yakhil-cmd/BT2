No vulnerability found.

**Rationale:** The vouch-proxy report describes a classic unauthenticated resource-exhaustion bug: an attacker-controlled integer taken from a request header is passed unchecked into `make([]slice, N)`, causing an unbounded heap allocation and OOM crash.

This bug class is explicitly out of scope per the scan method's exclusion rule 5 ("unbounded-loop or memory/storage-growth scenarios, oversized-input/flooding/generic resource-exhaustion claims and gas-only optimization"). Beyond that exclusion, investigation of the Polkadot SDK shows this exact failure mode is already systematically guarded against at every boundary where attacker-controlled length/size values could drive an allocation:

- SCALE decoding of extrinsics enforces a hard memory ceiling via `DecodeWithMemLimit`/`decode_with_mem_limit` before any `Vec` is grown, e.g. `MAX_CALL_SIZE` enforcement in `decode_with_len`. [1](#0-0) 
- Contracts/revive sandbox memory reads validate the requested `len` against the actual buffer/memory bounds and a schedule-defined `max_memory_size` *before* allocating the destination `Vec`. [2](#0-1) 
- Wasm executor output extraction explicitly checks the returned `(ptr, len)` against the real Wasm memory size before allocating the output buffer, with an explicit comment calling out the exact DoS class being prevented. [3](#0-2) 
- `pallet-utility` computes `batched_calls_limit` from `sp_core::MAX_POSSIBLE_ALLOCATION` and the call size to bound batching before dispatch, rejecting oversized batches via `Error::TooManyCalls`. [4](#0-3) 
- XCM's `DoubleEncoded` decoder enforces a nesting/recursion depth limit during decode rather than blindly allocating based on an attacker-supplied count. [5](#0-4) 

There is no equivalent "parse an attacker-controlled integer straight into `Vec::with_capacity`/`make`" pattern reachable from a real unauthenticated entry point (signed extrinsic, unsigned extrinsic validation, contract call, or XCM barrier) in the indexed production code. Given both the explicit method exclusion and the absence of a demonstrable unguarded analog, no finding is reported.

### Citations

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L513-519)
```rust
		let mut input = CountedInput::new(input);

		// Decode the preamble using the same memory limit as we will use for the `call`.
		// The preamble is not that big, but we play it safe.
		let preamble =
			DecodeWithMemLimit::decode_with_mem_limit(&mut input, MAX_CALL_SIZE.saturating_add(1))?;

```

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L554-628)
```rust
	pub fn read_sandbox_memory(
		&self,
		memory: &[u8],
		ptr: u32,
		len: u32,
	) -> Result<Vec<u8>, DispatchError> {
		ensure!(len <= self.ext.schedule().limits.max_memory_size(), Error::<E::T>::OutOfBounds);
		let mut buf = vec![0u8; len as usize];
		self.read_sandbox_memory_into_buf(memory, ptr, buf.as_mut_slice())?;
		Ok(buf)
	}

	/// Read designated chunk from the sandbox memory into the supplied buffer.
	///
	/// Returns `Err` if one of the following conditions occurs:
	///
	/// - requested buffer is not within the bounds of the sandbox memory.
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

**File:** substrate/frame/utility/src/lib.rs (L140-171)
```rust
	#[pallet::extra_constants]
	impl<T: Config> Pallet<T> {
		/// The limit on the number of batched calls.
		fn batched_calls_limit() -> u32 {
			let allocator_limit = sp_core::MAX_POSSIBLE_ALLOCATION;
			let call_size = (core::mem::size_of::<<T as Config>::RuntimeCall>() as u32)
				.div_ceil(CALL_ALIGN) *
				CALL_ALIGN;
			// The margin to take into account vec doubling capacity.
			let margin_factor = 3;

			allocator_limit / margin_factor / call_size
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn integrity_test() {
			// If you hit this error, you need to try to `Box` big dispatchable parameters.
			assert!(
				core::mem::size_of::<<T as Config>::RuntimeCall>() as u32 <= CALL_ALIGN,
				"Call enum size should be smaller than {} bytes.",
				CALL_ALIGN,
			);
		}
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Too many calls batched.
		TooManyCalls,
	}
```

**File:** polkadot/xcm/src/double_encoded.rs (L108-129)
```rust
impl<T> Decode for DoubleEncoded<T>
where
	T: Decode,
{
	fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
		let mut obj = Self { encoded: Vec::<u8>::decode(input)?, decoded: None };

		// If it's a local call, we also decode the inner double encoded object,
		// in order to make sure that its heap memory is accounted for.
		nesting_count::using_once(&mut 0, || {
			nesting_count::with(|count| {
				descend_ref_and_check_depth(
					count,
					RECURSION_LIMIT as u32,
					DECODE_RECURSION_LIMIT_MSG,
				)
			})
			.unwrap_or(Err("Could not access nesting_count env variable".into()))?;

			let mut nested_input =
				NestedInput { downstream_input: input, encoded: &obj.encoded[..], depth: 0 };
			let decoded = T::decode(&mut nested_input)?;
```
