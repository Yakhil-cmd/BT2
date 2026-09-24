Based on my investigation, the closest structural analog to Bluetooth Mesh Proxy SAR reassembly in the Polkadot SDK is the Cumulus XCMP queue's inbound page reassembly, where concatenated fragments (`VersionedXcm` items) sent by a sibling parachain are split back into individual messages via `take_first_concatenated_xcm`/`take_first_concatenated_xcms` and `handle_xcms_page`.

Unlike the NimBLE bug class (unbounded append across SAR fragments + unchecked reassembly failure passed to the application), this code path in `cumulus/pallets/xcmp-queue/src/lib.rs` is explicitly guarded at every step:

- Outbound fragment appends are bounded and checked against `max_message_size`/`T::MaxPageSize` before any mutation, returning `MessageSendError::TooBig` on overflow rather than growing unboundedly. [1](#0-0) 
- Inbound decoding uses a `WeightMeter` and `MAX_XCM_DECODE_DEPTH` depth limit, so decode work/allocation is metered and bounded, not unbounded append. [2](#0-1) 
- On decode failure, `take_first_concatenated_xcms` returns the error together with the partial batch, and `handle_xcms_page` explicitly stops processing that page (`can_process_next_batch = false`) and logs it as dropped rather than passing broken/reassembled data onward silently.
<invoke name="read_file">
<parameter name="file_path">cumulus/pallets/xcmp-queue/src/lib.rs</parameter>
<parameter name="repo_name">hirayap/polkadot-sdk--008</parameter>
<parameter name="start_line">980</parameter>
<parameter name="end_line">1017</parameter>
</invoke>

### Citations

**File:** cumulus/pallets/xcmp-queue/src/lib.rs (L591-601)
```rust
		let max_message_size = channel_info.max_message_size.min(T::MaxPageSize::get()) as usize;
		let format_size = format.encoded_size();
		// We check the encoded fragment length plus the format size against the max message size
		// because the format is concatenated if a new page is needed.
		let size_to_check = encoded_fragment
			.len()
			.checked_add(format_size)
			.ok_or(MessageSendError::TooBig)?;
		if size_to_check > max_message_size {
			return Err(MessageSendError::TooBig);
		}
```

**File:** cumulus/pallets/xcmp-queue/src/lib.rs (L793-807)
```rust
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
```
