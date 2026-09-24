No vulnerability found for this question.

Investigation summary: The .NET advisory's root cause is a length-prefixed field being decoded and used to allocate memory without validating it against the actual remaining payload size before allocation. I searched for equivalent patterns across Polkadot SDK's untrusted-input decode boundaries (extrinsic decoding, XCM message decoding, bridge/Snowbridge message payload decoding, contract sandbox memory reads), and every one of these paths explicitly validates length/size against actual remaining data or a hard limit *before* allocating:

- WASM host->runtime output extraction explicitly checks the claimed length against actual WASM memory size before allocating, with a comment describing exactly this DoS pattern: `extract_output_data` in [1](#0-0) .
- `UncheckedExtrinsic` decoding uses `DecodeWithMemLimit`/`CountedInput` to bound the allocation to `MAX_CALL_SIZE`, verifying afterward that the actual consumed length matches the untrusted length prefix: [2](#0-1) .
- XCM decoding via `VersionedXcm::decode_all_with_mem_and_depth_limit` wraps the input in a `MemTrackingInput` bounded by `MAX_XCM_SIZE` before any decode occurs: [3](#0-2) .
- The XCMP queue's opaque-XCM splitting explicitly uses `split_at_checked` on the actual byte slice, returning an error rather than allocating if the untrusted length exceeds available data: [4](#0-3) .
- Contract sandbox memory reads (`read_sandbox_memory`, `read_sandbox_memory_as_unbounded`) validate the requested length against actual sandbox memory bounds before allocating a buffer: [5](#0-4) .
- Underlying SCALE decoding (`parity-scale-codec`, used pervasively) enforces bounds/memory-tracking via the `Input` trait's `on_before_alloc_mem`/`remaining_len` mechanisms, which is precisely the pattern the .NET fix (PR #7064) retrofitted after the fact.

Since the codebase consistently validates untrusted length fields against real remaining payload size (or a hard cap) *before* allocation at every user-reachable decode boundary I could locate, there is no demonstrable analog to the unbounded `grpc-status-details-bin`-style allocation bug in this repository's production code.

### Citations

**File:** substrate/client/executor/wasmtime/src/runtime.rs (L734-743)
```rust
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

**File:** polkadot/xcm/src/lib.rs (L392-407)
```rust
	pub fn decode_all_with_mem_and_depth_limit(
		input: &mut &[u8],
	) -> Result<VersionedXcm<C>, CodecError> {
		// Adds 1 byte to the `MAX_XCM_SIZE` as the decoding fails exactly at the given value and
		// the maximum should be allowed to fit in.
		let mut mem_tracking_input = MemTrackingInput::new(input, MAX_XCM_SIZE.saturating_add(1));
		let xcm =
			VersionedXcm::decode_with_depth_limit(MAX_XCM_DECODE_DEPTH, &mut mem_tracking_input)?;
		// We need to also make sure that we consumed all the input data, but we can't use
		// `decode_all()`, because it only accepts a byte slice as input.
		if !input.is_empty() {
			return Err(DECODE_ALL_ERR_MSG.into());
		}

		Ok(xcm)
	}
```

**File:** cumulus/pallets/xcmp-queue/src/lib.rs (L833-847)
```rust
	pub(crate) fn take_first_concatenated_opaque_xcm<'a>(
		data: &mut &'a [u8],
	) -> Result<BoundedSlice<'a, u8, MaxXcmpMessageLenOf<T>>, TakeXcmError> {
		let xcm_len = Compact::<u32>::decode(data).map_err(|error| {
			tracing::debug!(target: LOG_TARGET, ?error, "Failed to decode opaque XCM length");
			TakeXcmError::InvalidData
		})?;
		let (xcm_data, remaining_data) = match data.split_at_checked(xcm_len.0 as usize) {
			Some((xcm_data, remaining_data)) => (xcm_data, remaining_data),
			None => {
				tracing::debug!(target: LOG_TARGET, ?xcm_len, "Wrong opaque XCM length");
				return Err(TakeXcmError::InvalidData);
			},
		};
		*data = remaining_data;
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
