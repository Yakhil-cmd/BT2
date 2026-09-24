No vulnerability found for this question.

The reported issue is an Apache Thrift Ruby-bindings zlib decompression bomb in an unrelated ecosystem (Ruby, not Rust/FRAME). The closest conceptual analog in `polkadot-sdk`—decompression-bomb handling for blobs—is implemented in `sp_maybe_compressed_blob::decompress` at `substrate/primitives/maybe-compressed-blob/src/lib.rs:50-81`, which enforces a strict `bomb_limit` using a bounded reader (`decoder.take((bomb_limit + 1) as u64)`) and explicitly returns `Error::PossibleBomb` if the decompressed size exceeds the limit. [1](#0-0)  This function is used consistently at every real user-facing decompression boundary I could identify:

- PoV decompression in the parachain validation path uses `POV_BOMB_LIMIT` derived from `MAX_POV_SIZE`. [2](#0-1) [3](#0-2) 
- Validation code (WASM) decompression uses `CODE_BLOB_BOMB_LIMIT` / dynamic `validation_code_bomb_limit`. [4](#0-3) [5](#0-4) 
- Both oversized-code and oversized-PoV bomb rejection paths are covered by existing integration tests (`invalid_compressed_code_fails_prechecking`, `invalid_compressed_pov_fails_validation`). [6](#0-5) 

There is no `thrift` dependency or Ruby binding anywhere in this repository. No unbounded/unchecked decompression path was found that would allow an attacker-controlled payload to trigger unbounded memory/CPU amplification analogous to the Thrift bug; the existing bomb-limit checks are strict, checked before use, and covered by tests. Per the scan rules, generic resource-exhaustion/decompression-bomb claims without a demonstrable missing check are excluded, and no such missing check was found here.

### Citations

**File:** substrate/primitives/maybe-compressed-blob/src/lib.rs (L50-65)
```rust
fn read_from_decoder(
	decoder: impl Read,
	blob_len: usize,
	bomb_limit: usize,
) -> Result<Vec<u8>, Error> {
	let mut decoder = decoder.take((bomb_limit + 1) as u64);

	let mut buf = Vec::with_capacity(blob_len);
	decoder.read_to_end(&mut buf).map_err(|_| Error::Invalid)?;

	if buf.len() <= bomb_limit {
		Ok(buf)
	} else {
		Err(Error::PossibleBomb)
	}
}
```

**File:** cumulus/bin/pov-validator/src/main.rs (L113-118)
```rust
	let pov = sp_maybe_compressed_blob::decompress(&pov.block_data.0, POV_BOMB_LIMIT).map_err(
		|error| {
			tracing::error!(%error, "Failed to decompress `PoV`");
			anyhow::anyhow!("Failed to decompress `PoV`")
		},
	)?;
```

**File:** polkadot/primitives/src/v9/mod.rs (L462-469)
```rust
/// Maximum PoV size we support right now.
///
/// Used for:
/// * initial genesis for the Parachains configuration
/// * checking updates to this stored runtime configuration do not exceed this limit
/// * when detecting a PoV decompression bomb in the client
// NOTE: This value is used in the runtime so be careful when changing it.
pub const MAX_POV_SIZE: u32 = 10 * 1024 * 1024;
```

**File:** substrate/client/executor/common/src/runtime_blob/runtime_blob.rs (L40-45)
```rust
	pub fn uncompress_if_needed(wasm_code: &[u8]) -> Result<Self, WasmError> {
		use sp_maybe_compressed_blob::CODE_BLOB_BOMB_LIMIT;
		let wasm_code = sp_maybe_compressed_blob::decompress(wasm_code, CODE_BLOB_BOMB_LIMIT)
			.map_err(|e| WasmError::Other(format!("Decompression error: {:?}", e)))?;
		Self::new(&wasm_code)
	}
```

**File:** polkadot/runtime/parachains/src/runtime_api_impl/v13.rs (L599-603)
```rust
/// Implementation for `validation_code_bomb_limit` function from the runtime API
pub fn validation_code_bomb_limit<T: initializer::Config>() -> u32 {
	configuration::ActiveConfig::<T>::get().max_code_size *
		configuration::MAX_VALIDATION_CODE_COMPRESSION_RATIO
}
```

**File:** polkadot/node/core/pvf/tests/it/main.rs (L799-873)
```rust
// Checks that we cannot prepare oversized compressed code
#[tokio::test]
async fn invalid_compressed_code_fails_prechecking() {
	let host = TestHost::new().await;
	let raw_code = vec![2u8; VALIDATION_CODE_BOMB_LIMIT as usize + 1];
	let validation_code = sp_maybe_compressed_blob::compress_strongly(
		&raw_code,
		VALIDATION_CODE_BOMB_LIMIT as usize + 1,
	)
	.unwrap();

	let res = host.precheck_pvf(&validation_code, Default::default()).await;

	assert_matches!(res, Err(PrepareError::CouldNotDecompressCodeBlob(_)));
}

// Checks that we cannot validate with oversized compressed code
#[tokio::test]
async fn invalid_compressed_code_fails_validation() {
	let host = TestHost::new().await;
	let pvd = PersistedValidationData {
		parent_head: Default::default(),
		relay_parent_number: 1u32,
		relay_parent_storage_root: H256::default(),
		max_pov_size: 4096 * 1024,
	};
	let pov = PoV { block_data: BlockData(Vec::new()) };

	let raw_code = vec![2u8; VALIDATION_CODE_BOMB_LIMIT as usize + 1];
	let validation_code = sp_maybe_compressed_blob::compress_strongly(
		&raw_code,
		VALIDATION_CODE_BOMB_LIMIT as usize + 1,
	)
	.unwrap();

	let result = host
		.validate_candidate(&validation_code, pvd, pov, Default::default(), H256::default())
		.await;

	assert_matches!(
		result,
		Err(ValidationError::Preparation(PrepareError::CouldNotDecompressCodeBlob(_)))
	);
}

// Checks that we cannot validate with an oversized PoV
#[tokio::test]
async fn invalid_compressed_pov_fails_validation() {
	let host = TestHost::new().await;
	let pvd = PersistedValidationData {
		parent_head: Default::default(),
		relay_parent_number: 1u32,
		relay_parent_storage_root: H256::default(),
		max_pov_size: 4096 * 1024,
	};
	let raw_block_data = vec![1u8; POV_BOMB_LIMIT + 1];
	let block_data =
		sp_maybe_compressed_blob::compress_weakly(&raw_block_data, POV_BOMB_LIMIT + 1).unwrap();
	let pov = PoV { block_data: BlockData(block_data) };

	let result = host
		.validate_candidate(
			test_parachain_halt::wasm_binary_unwrap(),
			pvd,
			pov,
			Default::default(),
			H256::default(),
		)
		.await;

	assert_matches!(
		result,
		Err(ValidationError::Invalid(InvalidCandidate::PoVDecompressionFailure))
	);
}
```
