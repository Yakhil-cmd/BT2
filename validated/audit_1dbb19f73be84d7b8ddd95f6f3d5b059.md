No vulnerability found for this question.

The CVE describes a memory-safety buffer over-read in FreeRADIUS's C code (`fr_dhcp_decode_suboptions()`), caused by a missing bounds check when parsing attacker-controlled DHCP suboption TLVs, leading to a read past the buffer end and a crash/DoS. This class of bug (raw pointer arithmetic reading past an allocated buffer due to unchecked length fields) is a C memory-safety failure mode.

I looked for an analogous pattern in the Polkadot SDK: places where untrusted, attacker-controlled binary data is parsed with length/offset fields that could cause an out-of-bounds read. The relevant decode paths I inspected are all bounds-checked in safe Rust:

- Contracts sandbox-memory reads use `memory.get(ptr..)` / `memory.get(ptr..ptr+len)` which return `None` (mapped to `Error::OutOfBounds`) rather than reading past the slice, before any decoding occurs. [1](#0-0) [2](#0-1) 
- SCALE codec's extrinsic/storage decoding paths (`UncheckedExtrinsic::decode`, `StorageInput::read`) check remaining length and return an `Err` rather than performing unchecked reads. [3](#0-2) [4](#0-3) 
- Networking request/response codecs validate declared length against a maximum before allocating/reading, and rely on `AsyncRead::read_exact`, which errors rather than over-reading. [5](#0-4) 

Rust's ownership/slice model inherently prevents the specific "read past the end of an allocated buffer into adjacent memory" primitive that the FreeRADIUS CVE exploits — any attempt to read beyond a slice's bounds in the safe-Rust code paths shown above results in a panic or a returned `Err`, not an out-of-bounds memory read. No unsafe pointer arithmetic parsing a length-prefixed suboption/TLV structure without a bounds check was found in the production decode paths reachable from an unprivileged extrinsic, XCM message, or network payload. Therefore no demonstrable Polkadot SDK analog to CVE-2017-10987 exists.

### Citations

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L590-601)
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
	}
```

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L614-628)
```rust
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

**File:** substrate/frame/support/src/storage/stream_iter.rs (L370-391)
```rust
	fn read(&mut self, into: &mut [u8]) -> Result<(), codec::Error> {
		// If there is still data left to be read from the state.
		if self.offset < self.total_length {
			if into.len() > self.buffer.capacity() {
				return self.read_big_item(into);
			} else if self.buffer_pos + into.len() > self.buffer.len() {
				self.fill_buffer()?;
			}
		}

		// Guard against `fill_buffer` not reading enough data or just not having enough data
		// anymore.
		if into.len() + self.buffer_pos > self.buffer.len() {
			return Err("Not enough data to fill the buffer".into());
		}

		let end = self.buffer_pos + into.len();
		into.copy_from_slice(&self.buffer[self.buffer_pos..end]);
		self.buffer_pos = end;

		Ok(())
	}
```

**File:** substrate/client/network/src/request_responses.rs (L1061-1076)
```rust
		// Read the length.
		let length = unsigned_varint::aio::read_usize(&mut io)
			.await
			.map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
		if length > usize::try_from(self.max_request_size).unwrap_or(usize::MAX) {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Request size exceeds limit: {} > {}", length, self.max_request_size),
			));
		}

		// Read the payload.
		let mut buffer = vec![0; length];
		io.read_exact(&mut buffer).await?;
		Ok(buffer)
	}
```
