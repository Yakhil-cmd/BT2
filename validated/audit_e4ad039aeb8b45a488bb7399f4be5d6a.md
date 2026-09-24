No vulnerability found for this question.

I searched for the CVE's core invariant violation — a length field extracted from an attacker-controlled encoded message being trusted to `memcpy`/copy data without validating it against the actual buffer size — across the Polkadot SDK's message/extrinsic/XCM decoding paths that are reachable via real user entry points.

Findings from the investigation:

- `cumulus/pallets/xcmp-queue/src/lib.rs` `take_first_concatenated_opaque_xcm` and `take_first_concatenated_xcm` both use `split_at_checked`/`CountedInput` and reject malformed length prefixes rather than blindly trusting them. [1](#0-0) 

- `substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs` `decode_with_len`/`Decode::decode` validates the declared length against `CountedInput::count()` and errors out on mismatch (`"Invalid length prefix"`), which is explicitly covered by a regression test. [2](#0-1) [3](#0-2) 

- `substrate/frame/message-queue/src/lib.rs` `peek_first`/`peek_index` check `payload_len <= item_slice.len()` before slicing the heap, defensively logging and returning `None` on corruption instead of overflowing. [4](#0-3) 

- The one place that does perform an unchecked, attacker-length-trusting slice copy analogous to the CVE — `decode_bytes` in `substrate/frame/revive/uapi/src/precompiles/utils.rs:138-152`, which reads a `bytes_len` word from `input` and does `out[..bytes_len].copy_from_slice(&input[32+offset..32+offset+bytes_len])` without bounds validation — is only ever invoked from `substrate/frame/revive/fixtures/sol_utils.rs`, a test/fixture helper, not from any production dispatch or precompile-call path. [5](#0-4) [6](#0-5) 

Since the only unchecked-length-copy analog is confined to test fixtures (explicitly excluded by the task's rejection criteria) and every genuine production decoding path I traced (XCMP, extrinsic decoding, message-queue heap) performs explicit bounds validation before copying/slicing, there is no demonstrable analog reachable through a real, unprivileged user entry point.

### Citations

**File:** cumulus/pallets/xcmp-queue/src/lib.rs (L836-846)
```rust
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
```

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L553-559)
```rust
		let encoded_call = Some(clone_bytes.1);

		if input.count() != len as u64 {
			return Err("Invalid length prefix".into());
		}

		Ok(Self { preamble, function, encoded_call, encoded_len: Some(len) })
```

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L1282-1291)
```rust
	#[test]
	fn invalid_length_prefix_is_detected() {
		let ux = Ex::new_bare(Call::Raw(vec![0u8; 0]).into());
		let mut encoded = ux.encode();

		let length = Compact::<u32>::decode(&mut &encoded[..]).unwrap();
		Compact(length.0 + 10).encode_to(&mut &mut encoded[..1]);

		assert_eq!(Ex::decode(&mut &encoded[..]), Err("Invalid length prefix".into()));
	}
```

**File:** substrate/frame/message-queue/src/lib.rs (L350-360)
```rust
		let mut item_slice = &self.heap[f..];
		if let Ok(h) = ItemHeader::<Size>::decode(&mut item_slice) {
			let payload_len = h.payload_len.into() as usize;
			if payload_len <= item_slice.len() {
				// impossible to truncate since is sliced up from `self.heap: BoundedVec<u8,
				// HeapSize>`
				return Some(BoundedSlice::defensive_truncate_from(&item_slice[..payload_len]));
			}
		}
		defensive!("message-queue: heap corruption");
		None
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

**File:** substrate/frame/revive/fixtures/sol_utils.rs (L130-137)
```rust
	).expect("delegate call to `Storage::take_storage` failed");

	let decoded = decode_bytes(&output[..], decode_output);
	if decoded == 0 {
		return None;
	} else {
		return Some(decoded);
	}
```
