No vulnerability found for this question.

The CVE-2023-22851 bug class is PHP-specific "object injection" via `unserialize()`, where a class name embedded in the serialized payload is used to dynamically instantiate an arbitrary PHP object, triggering that class's `__wakeup`/`__destruct` magic methods with attacker-controlled properties. This requires a serialization format that embeds type identity resolved dynamically at runtime.

The Polkadot SDK's SCALE codec (`Decode`/`Encode` traits) has no equivalent mechanism: decoding is monomorphized at compile time against a statically known target type, and there is no dynamic "instantiate whatever class name is encoded in the payload" step. All the extrinsic/XCM/contract-memory decode paths I inspected—`UncheckedExtrinsic::decode` [1](#0-0) , `DoubleEncoded<T>::decode` [2](#0-1) , `WrapperOpaque<T>::decode` [3](#0-2) , and contract sandbox memory decoding [4](#0-3) —decode into a fixed, statically-typed target enum/struct chosen by the Rust type system, not by attacker-supplied type metadata. Enum variants are selected only among the finite, developer-defined variant set via a discriminant byte, never by resolving an arbitrary class/type name to invoke side-effecting constructors or destructors.

Because there is no dynamic type resolution or magic-method invocation analog in this codebase's deserialization architecture, the specific "PHP Object Injection via unserialize" bug class does not have a demonstrable structural analog here, and forcing one would misrepresent the SCALE codec's design.

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

**File:** polkadot/xcm/src/double_encoded.rs (L108-129)
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
```

**File:** substrate/frame/support/src/traits/misc.rs (L1085-1091)
```rust
impl<T: Decode> Decode for WrapperOpaque<T> {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		Ok(Self(T::decode_all_with_depth_limit(
			crate::MAX_EXTRINSIC_DEPTH,
			&mut &<Vec<u8>>::decode(input)?[..],
		)?))
	}
```

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L590-628)
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
