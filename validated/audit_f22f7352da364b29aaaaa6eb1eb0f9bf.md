No vulnerability found for this question.

**Rationale**: I searched extensively across the Polkadot SDK codebase for the specific bug-class from the CVE — an attacker-controlled size/alignment computation that wraps around an integer boundary and produces a smaller-than-expected allocation, subsequently leading to a heap buffer overflow when the full (unwrapped) size of data is written.

Candidate locations examined, and why each is not a valid analog:

- `substrate/client/allocator/src/freeing_bump.rs` `Order::from_size` clamps and rejects any size above `MAX_POSSIBLE_ALLOCATION` before computing order/size, and `bump()` promotes size math to `u64` before comparing against actual memory size, so no `u32` wraparound is reachable. [1](#0-0) [2](#0-1) 
- `substrate/primitives/io/src/global_alloc.rs` computes `size + align.saturating_sub(8)` for the runtime allocator, but Rust's `Layout` invariant already guarantees `size` rounded up to `align` fits within `isize::MAX`, which is well under the `usize`/`u32` wraparound boundary — so this arithmetic can't overflow for any value reachable through a legitimately constructed `Layout`. [3](#0-2) 
- `substrate/frame/revive/src/vm/evm/memory.rs` `Memory::resize` uses `offset.saturating_add(len)` and hard-rejects any target exceeding `EVM_MEMORY_BYTES` (1 MiB) before ever growing the buffer, and the call sites in `substrate/frame/revive/src/vm/evm/instructions/contract/call_helpers.rs` (`resize_memory`) only build the `offset..offset+len` range *after* this bounded `resize` call succeeds, so the addition can't wrap given attacker-controlled EVM stack values. [4](#0-3) [5](#0-4) 
- `substrate/frame/revive/src/vm/evm/util.rs` `as_usize_or_halt_with` explicitly rejects any `U256` value whose upper limbs are non-zero or whose low limb exceeds `usize::MAX`, preventing truncation/wraparound when converting attacker-supplied 256-bit EVM stack values (offsets/lengths) to native `usize`. [6](#0-5) 
- `substrate/frame/contracts/src/wasm/runtime.rs` `read_sandbox_memory` bounds `len` against `max_memory_size()` before allocating the buffer. [7](#0-6) 
- `substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs` bounds decoded call/preamble sizes by `MAX_CALL_SIZE` via `DecodeWithMemLimit`, and validates the actual consumed byte count against the declared length prefix, closing off the classic "declared length ≠ actual data / oversized preallocation" pattern. [8](#0-7) 

Across every allocation-size computation I traced that is reachable from unprivileged/attacker-controlled input (unsigned/signed extrinsic decoding, EVM interpreter memory operations, contract call-data buffers, the WASM/PolkaVM runtime allocator), the codebase consistently applies `saturating_*`/`checked_*` arithmetic and/or hard upper-bound checks *before* the allocation is performed, which forecloses the "integer wraparound → under-allocation → heap buffer overflow" pattern described in the ThreadX NetX Duo CVE. I did not find a reachable, unguarded analog to report.

### Citations

**File:** substrate/client/allocator/src/freeing_bump.rs (L142-150)
```rust
	fn from_size(size: u32) -> Result<Self, Error> {
		let clamped_size = if size > MAX_POSSIBLE_ALLOCATION {
			log::warn!(target: LOG_TARGET, "going to fail due to allocating {:?}", size);
			return Err(Error::RequestedAllocationTooLarge);
		} else if size < MIN_POSSIBLE_ALLOCATION {
			MIN_POSSIBLE_ALLOCATION
		} else {
			size
		};
```

**File:** substrate/client/allocator/src/freeing_bump.rs (L512-517)
```rust
	fn bump(bumper: &mut u32, size: u32, memory: &mut impl Memory) -> Result<u32, Error> {
		let required_size = u64::from(*bumper) + u64::from(size);

		if required_size > memory.size() {
			let required_pages =
				pages_from_size(required_size).ok_or_else(|| Error::AllocatorOutOfSpace)?;
```

**File:** substrate/primitives/io/src/global_alloc.rs (L51-60)
```rust
unsafe impl GlobalAlloc for RuntimeAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		let align = layout.align();
		let size = layout.size();

		// Allocate for the required size, plus a potential alignment.
		//
		// As the host side already aligns the pointer by `8`, we only need to account for any
		// excess.
		let ptr = crate::allocator::malloc((size + align.saturating_sub(8)) as u32);
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

**File:** substrate/frame/revive/src/vm/evm/instructions/contract/call_helpers.rs (L42-56)
```rust
pub fn resize_memory<'a, E: Ext>(
	interpreter: &mut Interpreter<'a, E>,
	offset: U256,
	len: U256,
) -> ControlFlow<Halt, Range<usize>> {
	let len = as_usize_or_halt::<E::T>(len)?;
	if len != 0 {
		let offset = as_usize_or_halt::<E::T>(offset)?;
		interpreter.memory.resize(offset, len)?;
		ControlFlow::Continue(offset..offset + len)
	} else {
		// unrealistic value so we are sure it is not used
		ControlFlow::Continue(usize::MAX..usize::MAX)
	}
}
```

**File:** substrate/frame/revive/src/vm/evm/util.rs (L20-34)
```rust
/// Helper function to convert U256 to usize, checking for overflow
pub fn as_usize_or_halt_with(value: U256, halt: impl Fn() -> Halt) -> ControlFlow<Halt, usize> {
	let limbs = value.0;
	if (limbs[0] > usize::MAX as u64) | (limbs[1] != 0) | (limbs[2] != 0) | (limbs[3] != 0) {
		ControlFlow::Break(halt())
	} else {
		ControlFlow::Continue(limbs[0] as usize)
	}
}

/// Helper function to convert U256 to usize, checking for overflow, with default OutOfGas
/// error
pub fn as_usize_or_halt<T: Config>(value: U256) -> ControlFlow<Halt, usize> {
	as_usize_or_halt_with(value, || Error::<T>::OutOfGas.into())
}
```

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L554-564)
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
