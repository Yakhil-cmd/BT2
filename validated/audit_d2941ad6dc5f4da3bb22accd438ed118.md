No vulnerability found for this question.

Based on my review, the polkadot-sdk codebase consistently applies bounded/limited decoding and heap-based (not variable-size stack) buffers for all attacker-reachable inputs I could locate, which is the exact bug class described in CVE-2017-9763 (a variable-size stack array sized from untrusted input causing stack exhaustion).

Specifically:
- `UncheckedExtrinsic` decoding enforces a `MAX_CALL_SIZE` memory limit and uses `DecodeWithMemTracking`/`CountedInput` rather than allocating a stack array sized by an attacker-supplied length [1](#0-0) .
- XCM's `DoubleEncoded` decoding enforces an explicit `RECURSION_LIMIT`/depth check before recursing, preventing unbounded stack growth from a crafted nested payload [2](#0-1) [3](#0-2) .
- `pallet-contracts`/`pallet-revive` sandbox-memory reads use explicit bounds checks (`memory.get(ptr..)`) and depth-limited decoding, or read into heap-allocated `Vec`s sized by validated lengths rather than raw attacker-controlled stack arrays [4](#0-3) [5](#0-4) .
- Fixed-size arrays (e.g., `[u8; N]`) used for cryptographic types are always read through bound-checked `read_into_buf`/`read_array` helpers, not variable-sized stack allocations driven by attacker input [6](#0-5) .
- The WASM/PVF executor uses a deterministic stack-height instrumentation and pre-sized native stack limits rather than unbounded variable-size stack arrays, and this is specifically tested for controlled trapping behavior [7](#0-6) [8](#0-7) .

I did not find any real, unprivileged, user-reachable code path (signed extrinsic, contract call, or XCM execution) where a variable-size stack array is allocated directly from an attacker-controlled length without a prior bound/depth check, which is the specific violated invariant in the CVE. No further analog could be substantiated with concrete file:line evidence and a reproducible PoC as required by the strict output rules.

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

**File:** polkadot/xcm/src/double_encoded.rs (L108-138)
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
			// If we didn't manage to consume any byte, this is a remote call, and it can't
			// be decoded locally.
			if nested_input.encoded.len() == obj.encoded.len() {
				let _ = nesting_count::with(|count| {
					count.saturating_dec();
				});

				return Ok(obj);
			}
```

**File:** polkadot/xcm/src/lib.rs (L63-69)
```rust
///
/// The limit is applied only for nested `DoubleEncoded<T>`
pub const RECURSION_LIMIT: u8 = 10;
/// The maximal number of instructions in an XCM before decoding fails.
///
/// This is a deliberate limit - not a technical one.
pub const MAX_INSTRUCTIONS_TO_DECODE: u8 = 100;
```

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L590-600)
```rust
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
```

**File:** substrate/frame/revive/src/vm/pvm.rs (L91-102)
```rust
	fn read(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, DispatchError> {
		let mut buf = vec![0u8; len as usize];
		self.read_into_buf(ptr, buf.as_mut_slice())?;
		Ok(buf)
	}

	/// Same as `read` but reads into a fixed size buffer.
	fn read_array<const N: usize>(&mut self, ptr: u32) -> Result<[u8; N], DispatchError> {
		let mut buf = [0u8; N];
		self.read_into_buf(ptr, &mut buf)?;
		Ok(buf)
	}
```

**File:** substrate/frame/revive/src/vm/pvm.rs (L456-470)
```rust
	fn decode_key(&self, memory: &mut M, key_ptr: u32, key_len: u32) -> Result<Key, TrapReason> {
		let res = match key_len {
			SENTINEL => {
				let mut buffer = [0u8; 32];
				memory.read_into_buf(key_ptr, buffer.as_mut())?;
				Ok(Key::from_fixed(buffer))
			},
			len => {
				ensure!(len <= limits::STORAGE_KEY_BYTES, Error::<E::T>::DecodingFailed);
				let key = memory.read(key_ptr, len)?;
				Key::try_from_var(key)
			},
		};

		res.map_err(|_| Error::<E::T>::DecodingFailed.into())
```

**File:** substrate/client/executor/wasmtime/src/runtime.rs (L361-379)
```rust
#[derive(Clone)]
pub struct DeterministicStackLimit {
	/// A number of logical "values" that can be pushed on the wasm stack. A trap will be triggered
	/// if exceeded.
	///
	/// A logical value is a local, an argument or a value pushed on operand stack.
	pub logical_max: u32,
	/// The maximum number of bytes for stack used by wasmtime JITed code.
	///
	/// It's not specified how much bytes will be consumed by a stack frame for a given wasm
	/// function after translation into machine code. It is also not quite trivial.
	///
	/// Therefore, this number should be chosen conservatively. It must be so large so that it can
	/// fit the [`logical_max`](Self::logical_max) logical values on the stack, according to the
	/// current instrumentation algorithm.
	///
	/// This value cannot be 0.
	pub native_stack_max: u32,
}
```

**File:** substrate/client/executor/runtime-test/src/lib.rs (L302-328)
```rust
	fn allocates_huge_stack_array(trap: bool) -> Vec<u8> {
		// Allocate a stack frame that is approx. 75% of the stack (assuming it is 1MB).
		// This will just decrease (stacks in wasm32-u-u grow downwards) the stack
		// pointer. This won't trap on the current compilers.
		let mut data = [0u8; 1024 * 768];

		// Then make sure we actually write something to it.
		//
		// If:
		// 1. the stack area is placed at the beginning of the linear memory space, and
		// 2. the stack pointer points to out-of-bounds area, and
		// 3. a write is performed around the current stack pointer.
		//
		// then a trap should happen.
		//
		for (i, v) in data.iter_mut().enumerate() {
			*v = i as u8; // deliberate truncation
		}

		if trap {
			// There is a small chance of this to be pulled up in theory. In practice
			// the probability of that is rather low.
			panic!()
		}

		data.to_vec()
	}
```
