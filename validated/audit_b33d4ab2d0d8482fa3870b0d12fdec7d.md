No vulnerability found for this question.

**Rationale:** The reported CVE describes unbounded zip decompression in Spring's `UnZipTransformer` lacking entry-size/count limits. Searching for an analog in `polkadot-sdk`, the closest conceptual match is decompression of untrusted blobs (PVF validation code and PoV block data) in `sp_maybe_compressed_blob`. However, this crate already enforces a strict `bomb_limit` on every decompression call: `read_from_decoder` truncates the reader with `.take((bomb_limit + 1) as u64)` and rejects any output exceeding the limit with `Error::PossibleBomb` [1](#0-0) . This bounded check is invoked consistently at both call sites that decompress attacker/network-supplied data: PVF code preparation via `prepare_artifact` using `pvf.validation_code_bomb_limit()` [2](#0-1)  and PoV decompression using `POV_BOMB_LIMIT` [3](#0-2) . Test coverage confirms oversized/bomb payloads are rejected rather than exhausting memory [4](#0-3) [5](#0-4) .

Since the exact violated invariant from the report (missing decompression size/entry bound) is already defended against by design in every reachable path handling untrusted compressed input, there is no demonstrable analog. Additionally, per the scan methodology, generic memory/resource-exhaustion claims are explicitly excluded from consideration even if a gap were found.

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

**File:** polkadot/node/core/pvf/prepare-worker/src/lib.rs (L299-305)
```rust
fn prepare_artifact(pvf: PvfPrepData) -> Result<PrepareOutcome, PrepareError> {
	let maybe_compressed_code = pvf.maybe_compressed_code();
	let raw_validation_code = sp_maybe_compressed_blob::decompress(
		&maybe_compressed_code,
		pvf.validation_code_bomb_limit() as usize,
	)
	.map_err(|e| PrepareError::CouldNotDecompressCodeBlob(e.to_string()))?;
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

**File:** polkadot/node/core/pvf/tests/it/main.rs (L799-813)
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
```

**File:** polkadot/node/core/pvf/tests/it/main.rs (L844-872)
```rust
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
```
