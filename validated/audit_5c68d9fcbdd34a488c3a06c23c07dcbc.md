No vulnerability found for this question.

The CVE-2021-21840 describes an integer-overflow-driven heap buffer overflow in a native C media-parsing library (GPAC's MPEG-4 `saio` atom handling) caused by unchecked arithmetic on attacker-controlled offset/size fields read directly into memory. I looked for a genuine Polkadot SDK analog — code paths where an unprivileged, signed-extrinsic-reachable actor supplies offset/length fields that are used in unchecked pointer/slice arithmetic leading to memory corruption or out-of-bounds access.

What I found instead:
- SCALE decoding of untrusted payloads (`UncheckedExtrinsic`, XCM `Xcm<Call>`, `VersionedXcm`) enforces explicit memory/depth/instruction-count limits rather than doing raw unchecked arithmetic on attacker-supplied lengths. [1](#0-0) [2](#0-1) [3](#0-2) 
- The `modexp` builtin precompile in `pallet-revive`, which parses attacker-controlled length words from EVM-ABI call data (structurally similar to the CVE's length-field parsing), explicitly bounds-checks each length field against a max size before allocating/reading, and uses a safe `read_input` helper that clamps to buffer bounds rather than doing raw pointer arithmetic. [4](#0-3) [5](#0-4) 
- The only place with unchecked-arithmetic-style offset/length slicing on a raw `&[u8]` buffer without bounds checks is `decode_bytes` in `pallet_revive_uapi::precompiles::utils`, but this function is only invoked from test fixture code (`substrate/frame/revive/fixtures/sol_utils.rs`) that decodes a response the same guest contract itself requested from a trusted built-in precompile — it's not reachable by an external attacker supplying arbitrary offset/length values through a real user entry point, and it's dependency/fixture-only code, which is explicitly out of scope. [6](#0-5) [7](#0-6) 

No production, attacker-reachable path exhibits the CVE's core invariant violation (unchecked arithmetic on attacker-controlled offset/size feeding directly into a heap write), so I'm not reporting a finding for this question.

### Citations

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

**File:** polkadot/xcm/src/utils.rs (L30-46)
```rust
pub fn decode_xcm_instructions<I: codec::Input, T: Decode>(
	input: &mut I,
) -> Result<Vec<T>, codec::Error> {
	instructions_count::using_once(&mut 0, || {
		let vec_len: u32 = <Compact<u32>>::decode(input)?.into();
		instructions_count::with(|count| {
			*count = count.saturating_add(vec_len);
			if *count > MAX_INSTRUCTIONS_TO_DECODE as u32 {
				return Err(codec::Error::from("Max instructions exceeded"));
			}
			Ok(())
		})
		.unwrap_or(Err(codec::Error::from("Error calling `instructions_count::with()`")))?;
		let decoded_instructions = decode_vec_with_len(input, vec_len as usize)?;
		Ok(decoded_instructions)
	})
}
```

**File:** cumulus/pallets/xcmp-queue/src/lib.rs (L800-807)
```rust
		let input_data = &mut &data[..];
		let mut input = codec::CountedInput::new(input_data);
		VersionedXcm::<()>::decode_with_depth_limit(MAX_XCM_DECODE_DEPTH, &mut input).map_err(
			|error| {
				tracing::debug!(target: LOG_TARGET, ?error, "Failed to decode XCM with depth limit");
				TakeXcmError::InvalidData
			},
		)?;
```

**File:** substrate/frame/revive/src/precompiles/builtin/modexp.rs (L60-92)
```rust
		let mut input_offset = 0;

		// Yellowpaper: whenever the input is too short, the missing bytes are
		// considered to be zero.
		let mut base_len_buf = [0u8; 32];
		read_input(&input, &mut base_len_buf, &mut input_offset);
		let mut exp_len_buf = [0u8; 32];
		read_input(&input, &mut exp_len_buf, &mut input_offset);
		let mut mod_len_buf = [0u8; 32];
		read_input(&input, &mut mod_len_buf, &mut input_offset);

		// reasonable assumption: this must fit within the Ethereum EVM's max stack size
		let max_size_big = BigUint::from(1024u32);

		let base_len_big = BigUint::from_bytes_be(&base_len_buf);
		if base_len_big > max_size_big {
			Err(DispatchError::from("unreasonably large base length"))?;
		}

		let exp_len_big = BigUint::from_bytes_be(&exp_len_buf);
		if exp_len_big > max_size_big {
			Err(DispatchError::from("unreasonably exponent length"))?;
		}

		let mod_len_big = BigUint::from_bytes_be(&mod_len_buf);
		if mod_len_big > max_size_big {
			Err(DispatchError::from("unreasonably large modulus length"))?;
		}

		// bounds check handled above
		let base_len = base_len_big.to_usize().expect("base_len out of bounds");
		let exp_len = exp_len_big.to_usize().expect("exp_len out of bounds");
		let mod_len = mod_len_big.to_usize().expect("mod_len out of bounds");
```

**File:** substrate/frame/revive/src/precompiles/builtin/modexp.rs (L213-228)
```rust
/// Copy bytes from input to target.
fn read_input(source: &[u8], target: &mut [u8], source_offset: &mut usize) {
	// We move the offset by the len of the target, regardless of what we
	// actually copy.
	let offset = *source_offset;
	*source_offset += target.len();

	// Out of bounds, nothing to copy.
	if source.len() <= offset {
		return;
	}

	// Find len to copy up to target len, but not out of bounds.
	let len = core::cmp::min(target.len(), source.len() - offset);
	target[..len].copy_from_slice(&source[offset..][..len]);
}
```

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

**File:** substrate/frame/revive/fixtures/sol_utils.rs (L109-137)
```rust
pub fn take_storage<A: HostFn>(flags: StorageFlags, key: &[u8], decode_output: &mut [u8]) -> Option<usize> {
	let mut buffer = [0u8; 512];

	let sel = solidity_selector("takeStorage(uint32,bool,bytes)");
	buffer[..4].copy_from_slice(&sel[..4]);

	let flags = encode_u32(flags.bits());
	buffer[4..36].copy_from_slice(&flags[..32]);

	encode_bool(false, &mut buffer[36..68]); // `is_fixed_key`
	let n = encode_bytes(key, &mut buffer[68..]);

	let mut output = [0u8; 512];
	let _ = A::delegate_call(
		CallFlags::empty(),
		&STORAGE_PRECOMPILE_ADDR,
		u64::MAX,       // How much ref_time to devote for the execution. u64::MAX = use all.
		u64::MAX,       // How much proof_size to devote for the execution. u64::MAX = use all.
		&[u8::MAX; 32], // No deposit limit.
		&buffer[..36 /* selector + `uint32` */ + 32 /* `bool` */ + n /* `bytes` */],
		Some(&mut &mut output[..]),
	).expect("delegate call to `Storage::take_storage` failed");

	let decoded = decode_bytes(&output[..], decode_output);
	if decoded == 0 {
		return None;
	} else {
		return Some(decoded);
	}
```
