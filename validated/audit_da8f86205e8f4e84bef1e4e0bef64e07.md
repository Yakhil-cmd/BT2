This report describes a double-free vulnerability in a C library (open-iscsi's iSNS attribute decoder) — an entirely unrelated codebase and memory-safety bug class (manual buffer freeing in C). Polkadot SDK is written in Rust, where the double-free bug class described (freeing a heap-allocated `attr` buffer twice via `isns_attr_list_remove` when a decode error path re-triggers free) is not structurally reproducible in safe Rust code — no unsafe manual memory management with reachable double-free semantics exists in the runtime/pallet code paths that decode network-attacker-controlled input (XCM messages, extrinsics, bridge proofs).

I looked for any analog decoding paths that might have use-after-free/double-drop equivalents (e.g., unsafe blocks, manual `Drop` misuse, double-decode of untrusted SCALE-encoded data, XCM message decoding, bridge proof decoding) to see if a genuine analog exists.No vulnerability found for this question.

I searched for any Rust analog to the double-free bug class described (freeing an allocated buffer twice during error-path re-entry in an attribute/message decoder reachable from unauthenticated network input). The relevant decoding paths in this codebase — `DoubleEncoded::decode` in [1](#0-0) , `VersionedXcm::decode_all_with_mem_and_depth_limit` in [2](#0-1) , and `take_first_concatenated_xcm`/`handle_xcmp_messages` in [3](#0-2)  and [4](#0-3)  — all use safe Rust ownership (`Vec`, `Option<T>`, SCALE `Decode`) rather than manual C-style buffer allocation/free. Error paths in these decoders return `Err(...)` and drop the partially-constructed value exactly once via Rust's ownership/`Drop` semantics; there is no manual `free()`/`libc::free` call, no raw-pointer buffer that gets released on both a normal and an error/retry path, and no `unsafe` block in these XCM/XCMP decoding paths that manually manages and could double-release heap memory for attacker-controlled network input.

The few `unsafe` code sites found (`polkadot/parachain/src/wasm_api.rs`, `substrate/primitives/runtime-interface/src/pass_by.rs`, `substrate/primitives/core/src/testing.rs`) construct slices/`Vec`s from host-allocated memory in the WASM host/guest FFI boundary, not from network-attacker-controlled iSNS/XCM-style attribute lists, and don't exhibit a reachable double-free/double-drop pattern analogous to the CVE. The bug class (C-style manual free-then-reuse-then-free-again on a decode error path) does not have a structural analog reachable through a real unprivileged user entry point (signed extrinsic, XCM execute/send, contract call) in this codebase.

### Citations

**File:** polkadot/xcm/src/double_encoded.rs (L108-153)
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
			obj.decoded = Some(decoded);

			// We need to also make sure that we consumed all the input data, but we can't use
			// `decode_all()`, because it only accepts a byte slice as input.
			if !nested_input.encoded.is_empty() {
				return Err(DECODE_ALL_ERR_MSG.into());
			}

			let _ = nesting_count::with(|count| {
				count.saturating_dec();
			});

			Ok(obj)
		})
	}
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

**File:** cumulus/pallets/xcmp-queue/src/lib.rs (L789-828)
```rust
	pub(crate) fn take_first_concatenated_xcm<'a>(
		data: &mut &'a [u8],
		meter: &mut WeightMeter,
	) -> Result<BoundedSlice<'a, u8, MaxXcmpMessageLenOf<T>>, TakeXcmError> {
		// Let's make sure that we can decode at least an empty xcm message.
		let base_weight = T::WeightInfo::take_first_concatenated_xcm(0);
		if meter.try_consume(base_weight).is_err() {
			tracing::error!("Out of weight; could not decode all; dropping");
			return Err(TakeXcmError::OutOfWeight);
		}

		let input_data = &mut &data[..];
		let mut input = codec::CountedInput::new(input_data);
		VersionedXcm::<()>::decode_with_depth_limit(MAX_XCM_DECODE_DEPTH, &mut input).map_err(
			|error| {
				tracing::debug!(target: LOG_TARGET, ?error, "Failed to decode XCM with depth limit");
				TakeXcmError::InvalidData
			},
		)?;
		let (xcm_data, remaining_data) = data.split_at(input.count() as usize);
		*data = remaining_data;

		// Consume the extra weight that it took to decode this message.
		// This depends on the message len in bytes.
		// Saturates if it's over the limit.
		let extra_weight = T::WeightInfo::take_first_concatenated_xcm(xcm_data.len() as u32)
			.saturating_sub(base_weight);
		meter.consume(extra_weight);

		let xcm = BoundedSlice::try_from(xcm_data).map_err(|error| {
			tracing::error!(
				target: LOG_TARGET,
				?error,
				"Failed to take XCM after decoding: message is too long"
			);
			TakeXcmError::InvalidData
		})?;

		Ok(xcm)
	}
```

**File:** cumulus/pallets/xcmp-queue/src/lib.rs (L1119-1197)
```rust
impl<T: Config> XcmpMessageHandler for Pallet<T> {
	fn handle_xcmp_messages<'a, I: Iterator<Item = (ParaId, RelayBlockNumber, &'a [u8])>>(
		iter: I,
		max_weight: Weight,
	) -> (usize, Weight) {
		let mut num_processed_pages = 0;
		let mut meter = WeightMeter::with_limit(max_weight);

		let mut known_xcm_senders = BTreeSet::new();
		for (sender, _sent_at, mut data) in iter {
			// We can retry a page only if it's not the first one. If it was the first one,
			// and it failed it means that even with the max allocated weight we couldn't process
			// it completely. So we leave it partially processed.
			let can_retry_page = num_processed_pages > 0;

			let format = match XcmpMessageFormat::decode(&mut data) {
				Ok(f) => f,
				Err(_) => {
					tracing::error!("Unknown XCMP message format - dropping");
					num_processed_pages += 1;
					continue;
				},
			};

			match format {
				XcmpMessageFormat::Signals => {
					if let Err(_) =
						Self::handle_signals_page(sender, &mut data, &mut meter, can_retry_page)
					{
						break;
					}
					num_processed_pages += 1;
				},
				XcmpMessageFormat::ConcatenatedVersionedXcm |
				XcmpMessageFormat::ConcatenatedOpaqueVersionedXcm => {
					let encoding = match format {
						XcmpMessageFormat::ConcatenatedVersionedXcm => XcmEncoding::Simple,
						XcmpMessageFormat::ConcatenatedOpaqueVersionedXcm => {
							let mut all_channels = <OutboundXcmpStatus<T>>::get();
							if let Some(channel_details) =
								Self::try_get_or_insert_outbound_channel(&mut all_channels, sender)
							{
								channel_details
									.flags
									.notice_concatenated_opaque_versioned_xcm_support();
							}
							<OutboundXcmpStatus<T>>::put(all_channels);

							XcmEncoding::Double
						},
						_ => {
							// This branch is unreachable.
							num_processed_pages += 1;
							continue;
						},
					};

					if let Err(_) = Self::handle_xcms_page(
						sender,
						encoding,
						&mut data,
						&mut known_xcm_senders,
						&mut meter,
						can_retry_page,
					) {
						break;
					}
					num_processed_pages += 1;
				},
				XcmpMessageFormat::ConcatenatedEncodedBlob => {
					tracing::error!("Blob messages are unhandled - dropping page");
					num_processed_pages += 1;
					continue;
				},
			}
		}

		(num_processed_pages, meter.consumed())
	}
```
