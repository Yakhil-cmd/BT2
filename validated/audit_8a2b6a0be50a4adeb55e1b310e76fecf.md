Based on my investigation, I found one concrete analog worth reporting, but with important verification limits noted below.

### Title
Unchecked attacker-controlled length used to pre-allocate `Vec::with_capacity` during `UncheckedExtrinsic` decode - ([File: substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs])

### Summary
`UncheckedExtrinsic::decode` reads an outer `Compact<u32>` "declared length" directly from untrusted input and later uses that raw, unvalidated value to pre-allocate a `Vec<u8>` via `Vec::with_capacity(len)`, before any check that the underlying input actually contains that many bytes. This mirrors the `rmpv` advisory pattern: a length field taken from an untrusted buffer drives an eager allocation with no verification that sufficient data backs it.

### Finding Description
`Decode` for `UncheckedExtrinsic` reads the length prefix and passes it straight into `decode_with_len`: [1](#0-0) 

Inside `decode_with_len`, after the (bounded) preamble decode, the function creates a byte-clone buffer sized to the attacker-declared `len`, with no comparison of `len` against `MAX_CALL_SIZE` or the input's actual `remaining_len()` before allocating: [2](#0-1) 

The `Call` decode that follows is bounded by `MAX_CALL_SIZE.saturating_add(1)` via `decode_with_mem_limit`, and the preamble decode is likewise bounded: [3](#0-2) [4](#0-3) 

However, the `Vec::with_capacity(len)` call at line 546 is **not** gated by `MAX_CALL_SIZE` or by `on_before_alloc_mem` — it uses the raw outer `Compact<u32>` value directly. Only after decoding completes is `len` checked against the actually-consumed byte count: [5](#0-4) 

Since `Compact<u32>` can encode values up to `u32::MAX` (~4.29 GB) in as few as 5 bytes, a small crafted byte blob (declared length ≈ 4 GB, followed by a short valid preamble and minimal trailing bytes) triggers an eager multi-gigabyte allocation attempt at line 546 *before* the mismatch is ever detected at line 555. This is the direct analog of the `rmpv` CWE-400 pattern: pre-allocating based on a declared size without checking that the underlying buffer actually contains that much data.

I found a prdoc (`prdoc/stable2506/pr_8234.prdoc`) titled "Set a memory limit when decoding an `UncheckedExtrinsic`" describing a 16 MiB heap memory limit added for this exact decode path: [6](#0-5) 
This confirms the maintainers are aware of and actively hardening this exact decode surface (`MAX_CALL_SIZE`/`DEFAULT_MAX_CALL_SIZE = 16 * 1024 * 1024`), but the specific `Vec::with_capacity(len)` call for the `encoded_call` clone buffer appears to use the raw declared `len` rather than a value clamped to `MAX_CALL_SIZE` before allocating.

### Impact Explanation
If reachable with an attacker-controlled `len` unbounded by `MAX_CALL_SIZE`, this could cause a large, unvalidated memory allocation attempt (up to ~4 GB) from a very small input, i.e., a memory-based denial-of-service on whichever process performs the decode (e.g., a node parsing a submitted/gossiped extrinsic). This would be CWE-400, analogous to the `rmpv` advisory.

### Likelihood Explanation
**Uncertain — not fully verified.** I was unable to confirm, within tool budget, all of the following, which are necessary to establish real-world exploitability:
- Whether `len` is clamped elsewhere (e.g., in a caller) before reaching `decode_with_len`, given that `MAX_CALL_SIZE` is explicitly designed to bound this exact decode path per the prdoc found.
- The actual entry point and any pre-existing size limits (e.g., JSON-RPC `max_request_body_size`, libp2p/transaction-gossip message size caps, or txpool-level extrinsic size checks) that could already prevent an attacker from getting a mismatched declared-length/actual-data payload to this decoder.
- Whether `Vec::with_capacity` on the target platforms fails gracefully (returning an error) or aborts the process for oversized requests, and whether this differs from ordinary "large but valid" extrinsics which are already rejected by other size limits.

Given the explicit prior hardening work (`DEFAULT_MAX_CALL_SIZE`, `on_before_alloc_mem` mem-tracking machinery already threaded through this same code), it is plausible that this specific gap is already closed by a caller-side check I did not locate, or that it is bounded by transport-level limits that make the practical impact indistinguishable from ordinary oversized-input handling — which the assessment criteria explicitly instruct to reject as "generic resource-exhaustion."

### Recommendation
If not already covered by an equivalent bound elsewhere: validate `len` against `MAX_CALL_SIZE` (or the input's `remaining_len()`) before calling `Vec::with_capacity(len)` at `substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs:546`, e.g. by clamping the pre-allocation size or using `on_before_alloc_mem` prior to allocating, consistent with the mem-tracking already applied to the preamble and call decoding in the same function.

### Proof of Concept
Not executed. I did not have terminal/code-execution access to construct and run a concrete SCALE-encoded byte sequence (`Compact<u32>` declared length near `u32::MAX` + minimal valid preamble bytes) against `UncheckedExtrinsic::decode` to confirm the allocation size and observe actual behavior (error vs. abort vs. successful huge allocation). This finding is reported as an analog requiring further confirmation, not a proven, reproduced vulnerability — I recommend a Devin session with Rust execution access to build a minimal `codec`-based reproduction against this exact `decode`/`decode_with_len` path before treating this as bounty-eligible.

### Citations

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L515-518)
```rust
		// Decode the preamble using the same memory limit as we will use for the `call`.
		// The preamble is not that big, but we play it safe.
		let preamble =
			DecodeWithMemLimit::decode_with_mem_limit(&mut input, MAX_CALL_SIZE.saturating_add(1))?;
```

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L546-546)
```rust
		let mut clone_bytes = CloneBytes(&mut input, Vec::with_capacity(len));
```

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L550-551)
```rust
		let function =
			Call::decode_with_mem_limit(&mut clone_bytes, MAX_CALL_SIZE.saturating_add(1))?;
```

**File:** substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs (L555-557)
```rust
		if input.count() != len as u64 {
			return Err("Invalid length prefix".into());
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

**File:** prdoc/stable2506/pr_8234.prdoc (L4-9)
```text
title: Set a memory limit when decoding an `UncheckedExtrinsic`

doc:
  - audience: Runtime Dev
    description: |
      This PR sets a 16 MiB heap memory limit when decoding an `UncheckedExtrinsic`.
```
