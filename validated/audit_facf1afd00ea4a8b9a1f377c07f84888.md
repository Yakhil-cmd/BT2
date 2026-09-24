No vulnerability found for this question.

Investigation summary: The Liferay bug is a classic "trust the client-declared size parameter instead of validating the actual payload size" flaw. I looked for an analogous pattern in polkadot-sdk — places where a runtime-facing entry point accepts a user-supplied length/size parameter that is used for a security-relevant decision (fee/weight charging, storage bound enforcement, buffer allocation) while the actual payload size is not independently verified against it.

The closest structural analog is `pallet_preimage`'s `note_preimage` extrinsic, but it does not reproduce the flaw: the length used for both the weight charge and the `MAX_SIZE` bound check is derived directly from the actual submitted `Vec<u8>` (`bytes.len() as u32`), not from a separate caller-supplied length field, and `note_bytes` enforces `ensure!(len <= MAX_SIZE, Error::<T>::TooBig)` before any storage write. [1](#0-0) [2](#0-1) 

Similarly, in `frame_contracts`/`frame_revive`, all sandbox-memory reads that use caller-supplied length/pointer arguments (e.g. `read_sandbox_memory`, `write_sandbox_output`) explicitly bound-check the requested length against the actual accessible memory or a schedule-defined maximum before allocating/copying, and gas/weight is charged based on the length actually used, not an unchecked declared value. [3](#0-2) [4](#0-3) [5](#0-4) 

Per the scan rules, "oversized-input/flooding/generic resource-exhaustion claims" and "unbounded-loop or memory/storage-growth scenarios" must be rejected outright, which is exactly the bug class the Liferay report represents. I found no location where a Polkadot SDK entry point accepts an attacker-controlled declared size distinct from and unchecked against the real payload size in a way that would bypass an existing bound (the discriminator that would make this a genuine analog rather than excluded noise). Given both the absence of a matching root cause and the explicit exclusion criteria, no reportable analog exists.

### Citations

**File:** substrate/frame/preimage/src/lib.rs (L198-204)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::note_preimage(bytes.len() as u32))]
		pub fn note_preimage(origin: OriginFor<T>, bytes: Vec<u8>) -> DispatchResultWithPostInfo {
			// We accept a signed origin which will pay a deposit, or a root origin where a deposit
			// is not taken.
			let maybe_sender = Self::ensure_signed_or_manager(origin)?;
			let (system_requested, _) = Self::note_bytes(bytes.into(), maybe_sender.as_ref())?;
```

**File:** substrate/frame/preimage/src/lib.rs (L332-338)
```rust
	fn note_bytes(
		preimage: Cow<[u8]>,
		maybe_depositor: Option<&T::AccountId>,
	) -> Result<(bool, T::Hash), DispatchError> {
		let hash = T::Hashing::hash(&preimage);
		let len = preimage.len() as u32;
		ensure!(len <= MAX_SIZE, Error::<T>::TooBig);
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

**File:** substrate/client/executor/wasmtime/src/runtime.rs (L734-742)
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
```
