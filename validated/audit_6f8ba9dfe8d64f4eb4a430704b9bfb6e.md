No vulnerability found for this question.

The polkadot-sdk analog to the EVM `EcPairing` precompile is `Bn128Pairing` in `pallet-revive`, implemented at [1](#0-0) . Unlike the buggy `EcPairing.yul` contract described in the report (which erroneously returned 64 bytes), this implementation computes the boolean pairing check result as a `U256` and returns it via `ret_val.to_big_endian()` into a `Vec<u8>`, which is exactly 32 bytes as required by EIP-197 [2](#0-1) . This is confirmed by both the test vectors and the integration test, which show a 32-byte (64 hex char) output for the pairing precompile at address `0x8` [3](#0-2)  and [4](#0-3) .

There is no reachable code path where this precompile returns 64 bytes or any length other than 32 bytes — the return buffer size is fixed by `U256::to_big_endian()`, not attacker-controlled input. `Bn128Add` and `Bn128Mul` intentionally return 64 bytes because that matches their respective EIP specs (EIP-196), which is correct behavior, not a bug [5](#0-4) . No violated invariant, attacker-controlled input, or missing check analogous to the reported EVM bug class exists in this Rust/FRAME implementation.

### Citations

**File:** substrate/frame/revive/src/precompiles/builtin/bn128.rs (L31-55)
```rust
impl<T: Config> PrimitivePrecompile for Bn128Add<T> {
	type T = T;
	const MATCHER: BuiltinAddressMatcher = BuiltinAddressMatcher::Fixed(NonZero::new(0x6).unwrap());
	const HAS_CONTRACT_INFO: bool = false;

	fn call(
		_address: &[u8; 20],
		input: Vec<u8>,
		env: &mut impl Ext<T = Self::T>,
	) -> Result<Vec<u8>, Error> {
		env.frame_meter_mut().charge_weight_token(RuntimeCosts::Bn128Add)?;

		let p1 = read_point(&input, 0)?;
		let p2 = read_point(&input, 64)?;

		let mut buf = [0u8; 64];
		if let Some(sum) = AffineG1::from_jacobian(p1 + p2) {
			// point not at infinity
			sum.x().to_big_endian(&mut buf[0..32]).expect("0..32 is 32-byte length; qed");
			sum.y().to_big_endian(&mut buf[32..64]).expect("32..64 is 32-byte length; qed");
		}

		Ok(buf.to_vec())
	}
}
```

**File:** substrate/frame/revive/src/precompiles/builtin/bn128.rs (L85-164)
```rust
pub struct Bn128Pairing<T>(PhantomData<T>);

impl<T: Config> PrimitivePrecompile for Bn128Pairing<T> {
	type T = T;
	const MATCHER: BuiltinAddressMatcher = BuiltinAddressMatcher::Fixed(NonZero::new(0x8).unwrap());
	const HAS_CONTRACT_INFO: bool = false;

	fn call(
		_address: &[u8; 20],
		input: Vec<u8>,
		env: &mut impl Ext<T = Self::T>,
	) -> Result<Vec<u8>, Error> {
		if !input.len().is_multiple_of(192) {
			Err(DispatchError::from("invalid input length"))?;
		}

		let ret_val = if input.is_empty() {
			env.frame_meter_mut().charge_weight_token(RuntimeCosts::Bn128Pairing(0))?;
			U256::one()
		} else {
			// (a, b_a, b_b - each 64-byte affine coordinates)
			let elements = input.len() / 192;
			env.frame_meter_mut()
				.charge_weight_token(RuntimeCosts::Bn128Pairing(elements as u32))?;

			let mut vals = Vec::new();
			for i in 0..elements {
				let offset = i * 192;
				let a_x = Fq::from_slice(&input[offset..offset + 32])
					.map_err(|_| DispatchError::from("Invalid a argument x coordinate"))?;

				let a_y = Fq::from_slice(&input[offset + 32..offset + 64])
					.map_err(|_| DispatchError::from("Invalid a argument y coordinate"))?;

				let b_a_y = Fq::from_slice(&input[offset + 64..offset + 96]).map_err(|_| {
					DispatchError::from("Invalid b argument imaginary coeff x coordinate")
				})?;

				let b_a_x = Fq::from_slice(&input[offset + 96..offset + 128]).map_err(|_| {
					DispatchError::from("Invalid b argument imaginary coeff y coordinate")
				})?;

				let b_b_y = Fq::from_slice(&input[offset + 128..offset + 160]).map_err(|_| {
					DispatchError::from("Invalid b argument real coeff x coordinate")
				})?;

				let b_b_x = Fq::from_slice(&input[offset + 160..offset + 192]).map_err(|_| {
					DispatchError::from("Invalid b argument real coeff y coordinate")
				})?;

				let b_a = Fq2::new(b_a_x, b_a_y);
				let b_b = Fq2::new(b_b_x, b_b_y);
				let b =
					if b_a.is_zero() && b_b.is_zero() {
						G2::zero()
					} else {
						G2::from(AffineG2::new(b_a, b_b).map_err(|_| {
							DispatchError::from("Invalid b argument - not on curve")
						})?)
					};
				let a =
					if a_x.is_zero() && a_y.is_zero() {
						G1::zero()
					} else {
						G1::from(AffineG1::new(a_x, a_y).map_err(|_| {
							DispatchError::from("Invalid a argument - not on curve")
						})?)
					};
				vals.push((a, b));
			}

			let mul = pairing_batch(&vals);

			if mul == Gt::one() { U256::one() } else { U256::zero() }
		};

		let buf = ret_val.to_big_endian();
		Ok(buf.to_vec())
	}
}
```

**File:** substrate/frame/revive/src/tests/pvm.rs (L4779-4783)
```rust
			"Bn128Pairing",
			H160::from_low_u64_be(8),
			hex!("1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa").to_vec(),
			hex!("0000000000000000000000000000000000000000000000000000000000000001").to_vec(),
		),
```

**File:** substrate/frame/revive/src/precompiles/builtin/testdata/8-bn128pairing.json (L1-8)
```json
[
  {
    "Input": "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
    "Expected": "0000000000000000000000000000000000000000000000000000000000000001",
    "Name": "jeff1",
    "Gas": 113000,
    "NoBenchmark": false
  },
```
