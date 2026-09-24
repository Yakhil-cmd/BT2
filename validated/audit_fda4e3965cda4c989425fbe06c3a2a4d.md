### Title
Ethereum transaction RLP decoding in pallet-revive silently accepts trailing bytes - ([File: substrate/frame/revive/src/evm/api/rlp_codec.rs])

### Summary
`TransactionSigned::decode()` in `pallet-revive` decodes Ethereum-formatted transactions submitted via `eth_transact` using the third-party `rlp` crate's `rlp::decode::<T>()` helper, applied to the full submitted payload slice, without verifying that the entire input buffer was consumed by the decoded RLP item. This mirrors the reported Erigon defect exactly: RLP is self-length-delimited, so a decoder that does not assert "no bytes remain after the item" will accept `valid_rlp || garbage` as if it were `valid_rlp` alone.

### Finding Description [1](#0-0) 

```rust
pub fn decode(data: &[u8]) -> Result<Self, rlp::DecoderError> {
    ...
    match first_byte {
        TYPE_EIP2930 => rlp::decode::<Transaction2930Signed>(&data[1..]).map(Into::into),
        TYPE_EIP1559 => rlp::decode::<Transaction1559Signed>(&data[1..]).map(Into::into),
        TYPE_EIP4844 => rlp::decode::<Transaction4844Signed>(&data[1..]).map(Into::into),
        TYPE_EIP7702 => rlp::decode::<Transaction7702Signed>(&data[1..]).map(Into::into),
        _ => Err(rlp::DecoderError::Custom("Unknown transaction type")),
    }
    ...
    rlp::decode::<TransactionLegacySigned>(data).map(Into::into)
}
```

`rlp::decode` internally constructs an `Rlp` view over the given slice and decodes exactly one top-level item from the front of it; because the RLP prefix self-declares the payload's length, any trailing bytes after that declared length are simply never inspected — the function returns `Ok` as long as the *leading* bytes form a valid transaction, regardless of what (if anything) follows.

This is called from `try_into_checked_extrinsic` at [2](#0-1)  where `payload` is the raw byte string an unprivileged caller submits (the `eth_transact` signed Ethereum-style transaction body). The decoded transaction's signature is verified against `unsigned_payload()`, which is re-derived purely from the *decoded struct fields* (not from the raw submitted bytes), so appending extra bytes after the valid RLP encoding does not invalidate the ECDSA signature check performed by `recover_eth_address()`.

Separately, `encoded_len`/`payload.to_vec()` (the full, garbage-including byte string) is what gets stored/used for proof-size and fee-length accounting (`CreateCallMode::ExtrinsicExecution(encoded_len as u32, payload.to_vec())`), while the semantic transaction (nonce, gas, call data, value, signature) is derived solely from the RLP-decoded prefix. This creates a byte-for-byte multiplicity: an unbounded number of distinct outer byte strings (same valid RLP prefix + arbitrary suffix) all decode to the *same* semantic transaction and the *same* recovered signer/nonce/signature, yet they are distinct as raw blobs.

### Impact Explanation
Unlike Erigon vs. other Ethereum execution clients — where the same raw bytes are independently parsed by multiple, differently-implemented nodes, so a lenient parser causes a literal chain split — Substrate/pallet-revive does not have that multi-implementation attack surface for its own extrinsic body: there is one authoritative decode path (`TransactionSigned::decode`) used uniformly by all Polkadot SDK-based nodes running the same runtime. This substantially weakens (but does not fully negate) the severity relative to the original Erigon report:

- It does **not** by itself constitute a cross-client consensus split analogous to Erigon vs. Geth/Reth/Besu, because there is no competing decoder implementation among honest nodes running the same runtime WASM.
- It **does** violate the same intrinsic-validity invariant the Yellow Paper describes ("well-formed RLP, with no additional trailing bytes"), and it does allow an attacker-controlled, non-canonical byte string to be treated as identical to the canonical Ethereum-standard-encoded transaction for dispatch purposes, while diverging from it for hashing/length purposes (see below).
- The concrete, provable consequence I can establish from the code is a **byte-length/proof-size accounting discrepancy**: the fee/weight length charge is computed from `payload.len()` (the full submitted bytes, including any attacker-appended suffix) while the semantic dispatch content is unaffected by the suffix. This lets a submitter inflate (self-harm) or, if `encoded_len` is derived elsewhere (e.g., truncated at the actual extrinsic-pool length rather than the raw payload) create a mismatch between the length used for weight/fee accounting and the length actually needed to represent the transaction. I was not able to fully trace, within the remaining iterations, whether `encoded_len` is sourced from the outer SCALE extrinsic length (in which case it is bounded and cross-checked by `frame_system::CheckWeight`/length limits) or from an unchecked value attacker-controlled independently of that check — this is the key remaining uncertainty.
- A second unverified but plausible consequence is a **transaction-hash/identity ambiguity** in `pallet-revive-eth-rpc`: if the externally-reported Ethereum transaction hash is computed as `keccak256(raw_submitted_payload)` (standard Ethereum semantics) while dispatch/signature-recovery is keyed off the decoded RLP prefix only, then two distinct submissions (canonical bytes vs. canonical-bytes-plus-garbage) would have different Ethereum tx hashes but identical on-chain effects (same nonce, same call, same signer), which could confuse RPC clients, receipt indexing, or duplicate-detection logic that keys on tx hash. I could not confirm this within the available searches because `receipt_extractor.rs`/`rlp_codec.rs`'s hash-computation call sites were not fully inspected before the iteration budget ran out.

Given the uncertainty above, I cannot assert Critical/High impact (theft, unbacked issuance, unauthorized dispatch, or deterministic chain failure) with the evidence gathered. The clearly demonstrable defect is a decoding/spec-conformance bug (non-canonical transaction acceptance), not a proven fund-loss or consensus-halting bug within this single-execution-engine architecture.

### Likelihood Explanation
Trivial to trigger: any unprivileged user calling `eth_transact` (or any equivalent entry point that ultimately calls `TransactionSigned::decode`) can append arbitrary trailing bytes to an otherwise valid, correctly signed RLP transaction and have it accepted identically to the canonical encoding. No privileged role, governance, or malicious peer is required — it is exercised purely through a normal signed transaction submission.

### Recommendation
After each successful `rlp::decode::<T>(bytes)` call in `TransactionSigned::decode` (`substrate/frame/revive/src/evm/api/rlp_codec.rs`), explicitly verify that the decoded item's RLP-declared length equals `bytes.len()` (e.g., by using `Rlp::new(bytes)` and checking `rlp.as_raw().len() == bytes.len()` / that `rlp.payload_info()?.total() == bytes.len()`), rejecting the transaction with a decoding error if any trailing bytes remain — directly analogous to the `endStrictEncoding` fix suggested for Erigon. Additionally, audit and confirm that `encoded_len` used for fee/weight/proof-size accounting is derived from a value bounded by `frame_system::CheckWeight`'s enforced extrinsic length (not an independently attacker-suppliable length), and confirm whether any RPC-facing transaction-hash computation hashes the raw submitted bytes versus the canonical re-encoded bytes, unifying on one canonical representation.

### Proof of Concept
No executable PoC was run against this repository. A conceptual reproduction, follows the same technique as the referenced Erigon test:
1. Construct any valid, correctly signed legacy/EIP-1559/2930/7702/4844 Ethereum transaction byte string `valid_tx`.
2. Append arbitrary trailing bytes: `malicious_tx = valid_tx || [0u8; N]`.
3. Call `TransactionSigned::decode(&malicious_tx)` (as exercised via `EthExtra::try_into_checked_extrinsic`, `substrate/frame/revive/src/evm/runtime.rs:354`).
4. Expected (spec-conformant) behavior: decode error due to trailing bytes.
5. Actual behavior (unverified by direct test execution, inferred from code path and `rlp` crate semantics): decode succeeds, signature recovery succeeds, and the transaction is dispatched as if `malicious_tx == valid_tx`.

This inference is based on static code review only — I did not execute a Rust test in this session to empirically confirm the `rlp` crate's exact trailing-byte behavior for this repository's pinned `rlp` crate version, since that dependency's source is external to the indexed repository. A background Devin session with terminal access would be needed to run `cargo test` against a crafted `TestTrailingBytes`-equivalent unit test in `substrate/frame/revive/src/evm/api/rlp_codec.rs`'s existing `#[cfg(test)] mod test` to obtain definitive pass/fail evidence, and to trace the exact source of `encoded_len` and any RPC-side transaction-hash computation to establish concrete financial/consensus impact.

### Citations

**File:** substrate/frame/revive/src/evm/api/rlp_codec.rs (L100-119)
```rust
	/// Decode the Ethereum transaction from bytes.
	pub fn decode(data: &[u8]) -> Result<Self, rlp::DecoderError> {
		if data.is_empty() {
			return Err(rlp::DecoderError::RlpIsTooShort);
		}
		let first_byte = data[0];

		// EIP-2718: Typed transactions use type identifiers in [0x00, 0x7f].
		if first_byte <= 0x7f {
			match first_byte {
				TYPE_EIP2930 => rlp::decode::<Transaction2930Signed>(&data[1..]).map(Into::into),
				TYPE_EIP1559 => rlp::decode::<Transaction1559Signed>(&data[1..]).map(Into::into),
				TYPE_EIP4844 => rlp::decode::<Transaction4844Signed>(&data[1..]).map(Into::into),
				TYPE_EIP7702 => rlp::decode::<Transaction7702Signed>(&data[1..]).map(Into::into),
				_ => Err(rlp::DecoderError::Custom("Unknown transaction type")),
			}
		} else {
			rlp::decode::<TransactionLegacySigned>(data).map(Into::into)
		}
	}
```

**File:** substrate/frame/revive/src/evm/runtime.rs (L354-357)
```rust
		let tx = TransactionSigned::decode(&payload).map_err(|err| {
			log::debug!(target: LOG_TARGET, "Failed to decode transaction: {err:?}");
			InvalidTransaction::Call
		})?;
```
