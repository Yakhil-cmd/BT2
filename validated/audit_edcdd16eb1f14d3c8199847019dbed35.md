No vulnerability found for this question.

The underlying CVE is a Linux kernel SCTP bug: `sctp_verify_asconf()`/`sctp_verify_param()` validate that an outer ASCONF parameter is large enough to hold a `sctp_addip_param` header, but never check that the *embedded* address parameter's self-declared length field stays within the outer parameter's bounds — leading to an out-of-bounds read when the length is later trusted by `af->from_addr_param()`. This is a classic C-style "trust an attacker-controlled length field embedded in a nested TLV, then do unchecked pointer arithmetic based on it" bug.

I looked for a structural analog in the Polkadot SDK: places where a length-prefixed/embedded parameter is decoded from untrusted, reachable input (extrinsics, XCM messages, trie nodes) and checked for a doubly-encoded value against a raw buffer bound.

- `substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs` decodes the extrinsic length prefix and cross-checks the actual consumed bytes against the declared `Compact<u32>` length via `CountedInput`, rejecting mismatches with `"Invalid length prefix"` [1](#0-0) .
- `cumulus/pallets/xcmp-queue/src/lib.rs`'s `take_first_concatenated_opaque_xcm` reads an embedded `Compact<u32>` length and uses `data.split_at_checked(xcm_len.0 as usize)`, which safely returns `None`/error rather than performing unchecked pointer math when the declared length exceeds the remaining buffer [2](#0-1) .
- `substrate/primitives/trie/src/node_codec.rs`'s `decode_plan` decodes embedded `Compact<u32>` lengths for branch/leaf values and children, then calls `input.take(count)`, which is bounds-checked against the underlying slice and returns `Error::BadFormat`/an `Err` rather than an OOB read [3](#0-2) .

In all of these cases, the SCALE codec's `Input` abstraction (and safe Rust slice indexing generally) performs bounds checking on every read rather than trusting an attacker-supplied length to compute a raw pointer offset. Any oversized embedded length results in a decode error (`Err`), not an out-of-bounds memory read/write. This is the same mechanism (memory-safe language + bounds-checked codec primitives) that structurally prevents the entire bug class the SCTP CVE represents. I found no location in the scanned production code where an embedded length field is used to slice/read memory without such a bounds check.

### Citations

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L1128-1136)
```rust
			if let Some((before_length, after_length)) =
				input.remaining_len()?.and_then(|a| before_length.map(|b| (b, a)))
			{
				let length = before_length.saturating_sub(after_length);

				if length != expected_length.0 as usize {
					return Err("Invalid length prefix".into());
				}
			}
```

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

**File:** substrate/primitives/trie/src/node_codec.rs (L125-148)
```rust
				let value = if branch_has_value {
					Some(if contains_hash {
						ValuePlan::Node(input.take(H::LENGTH)?)
					} else {
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						ValuePlan::Inline(input.take(count)?)
					})
				} else {
					None
				};
				let mut children = [
					None, None, None, None, None, None, None, None, None, None, None, None, None,
					None, None, None,
				];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if bitmap.value_at(i) {
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						let range = input.take(count)?;
						children[i] = Some(if count == H::LENGTH {
							NodeHandlePlan::Hash(range)
						} else {
							NodeHandlePlan::Inline(range)
						});
					}
```
