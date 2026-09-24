### Title
`hop_submit`'s signature omits the `recipients` list, letting anyone holding a captured `(data, signature, signer, submit_timestamp)` tuple register themselves as an authorized recipient - ([File: substrate/client/hop/src/types.rs])

### Summary
The Crestal report's root cause is that a signed request authorizes some parameters (`projectId`, `base64RecParam`, `serverURL`) but leaves other attacker-relevant parameters (`tokenId`, `privateWorkerAddress`) outside the signature, so anyone who obtains the signature can resubmit it with substituted values for the unsigned fields. The Polkadot-SDK "HOP" (Hand-Off Protocol) node feature reproduces the identical pattern: the `hop_submit` signature covers only the data hash and timestamp, but not the `recipients` list submitted in the very same call.

### Finding Description
`hop_submit(data, recipients, signature, signer, submit_timestamp)` is a public JSON-RPC entry point that any client of a HOP-enabled node can call [1](#0-0) . The signature that authenticates the request is computed as:

```
blake2_256(HOP_SUBMIT_CONTEXT || blake2_256(data) || submit_timestamp.to_le_bytes())
``` [2](#0-1) 

Nothing in this payload includes the `recipients` argument, even though `recipients` is decoded and stored alongside the signature by `do_submit`/`HopDataPool::insert` as the authoritative list of parties allowed to `hop_claim`/`hop_ack` the blob [3](#0-2) . The verification logic (in `HopDataPool::insert`, reached via `do_submit`) only re-derives `submit_signing_payload(hash, submit_timestamp)` and checks it against `signature`/`signer` — it never binds `recipients` into what is signed [4](#0-3) . The on-chain promotion path that the maintenance task builds from the same pool entry likewise carries only `data`, `signer`, `signature`, `submit_timestamp` — `recipients` is dropped entirely, confirming it was never part of the authenticated protocol data [5](#0-4) .

This is structurally identical to the Crestal bug class: a legitimately signed tuple `(data, signature, signer, submit_timestamp)` remains valid regardless of which `recipients` value accompanies it, because that field is never part of the signed message. Anyone in possession of a valid `(data, signature, signer, submit_timestamp)` tuple can call `hop_submit` against any HOP-enabled node with an arbitrary, self-chosen `recipients` list (subject only to the `MAX_RECIPIENTS` bound check [6](#0-5) ) and the request still validates successfully, since the check only re-verifies the hash/timestamp-based signature, not who is allowed to read the resulting entry.

### Impact Explanation
Since `recipients` gates who may successfully call `hop_claim`/`hop_ack` on a given node's `HopDataPool` entry to read the blob's plaintext, an attacker who can reconstruct or intercept a valid `(data, signature, signer, submit_timestamp)` tuple can submit it to any HOP-enabled node with themselves listed as a recipient, gaining unauthorized read access to hand-off data that was never intended for them. Because each node maintains its own independent, content-addressed pool (duplicate detection is per-node, keyed by `blake2_256(data)` [7](#0-6) ), the attacker's submission to a different node than the legitimate sender's target node is not rejected as a duplicate, so this is reachable without needing to beat a race against an existing entry on the same node. This breaks the confidentiality/authorization invariant of the recipient list — the analog of "worker censorship"/"illegitimate access" in the original report, here manifesting as unauthorized disclosure of hand-off data rather than fund theft.

### Likelihood Explanation
Exploitation requires the attacker to already possess the full `(data, signature, signer, submit_timestamp)` tuple — i.e., they must have observed a legitimate submission (e.g., through network capture of an unencrypted RPC session, a compromised or non-TLS RPC proxy the sender used, or by being a party the data was already shared with out-of-band). This is the same class of prerequisite the original report relies on (capturing a signed payload from a public mempool before it lands on-chain); it does not require any privileged runtime/validator/collator role, governance power, or key theft — only observation of data that transits an RPC channel not itself protected by this signature scheme. I was not able to verify from the indexed code whether the operational deployment guidance mandates TLS for HOP RPC endpoints, which would affect real-world exploitability; this should be checked directly in a live/full-repo review.

### Recommendation
Bind `recipients` (e.g. as a bounded, canonically-encoded list) into the `hop_submit` signing payload, e.g. `blake2_256(HOP_SUBMIT_CONTEXT || blake2_256(data) || recipients.encode() || submit_timestamp.to_le_bytes())`, and update `submit_signing_payload`/the on-chain re-derivation accordingly so the sender's signature authenticates exactly who is authorized to claim the data, consistent with the mitigation suggested in the source report ("sign all parameters").

### Proof of Concept
Deployment evidence: `hop_submit`'s wire format and verification are as documented in [8](#0-7)  and implemented in `do_submit`/`HopDataPool::insert`, confirming `recipients` is accepted as a separate, unauthenticated argument alongside the signature.

Failed guard: `submit_signing_payload` (`substrate/client/hop/src/types.rs:328`) never incorporates `recipients`, and the test suite exercises signature validity only against `data`/`submit_timestamp` (`submit_sig(&pair, &data, TEST_SUBMIT_TS)` in `substrate/client/hop/src/rpc.rs:552-568`), never against `recipients`, corroborating that mismatched/attacker-chosen recipient lists pass signature verification unchanged.

I did not execute a live integration test against a running node (no runtime/network access in this session); the above is based on static code inspection of the cited files. A concrete local repro would consist of: (1) constructing a valid `hop_submit` signature over some `data`/`submit_timestamp` as the legitimate sender, (2) replaying the identical `(data, signature, signer, submit_timestamp)` to a HOP RPC instance with a `recipients` list containing an attacker-controlled key instead of the sender's intended recipients, and (3) confirming `hop_submit` succeeds and the attacker's `hop_claim` against that entry returns the data — this should be run as a background Devin session against the `substrate/client/hop` test harness (`substrate/client/hop/src/rpc.rs` test module) to obtain pass/fail evidence before filing.

### Citations

**File:** substrate/client/hop/src/rpc.rs (L68-76)
```rust
	#[method(name = "hop_submit", blocking)]
	fn submit(
		&self,
		data: Bytes,
		recipients: Vec<Bytes>,
		signature: Bytes,
		signer: Bytes,
		submit_timestamp: u64,
	) -> RpcResult<SubmitResult>;
```

**File:** substrate/client/hop/src/types.rs (L40-46)
```rust
#[derive(Debug, Clone, Encode, Decode)]
pub struct Recipient {
	/// Ephemeral public key (MultiSigner: ed25519, sr25519, or ecdsa).
	pub signer: MultiSigner,
	/// Whether this recipient has acked receipt.
	pub claimed: bool,
}
```

**File:** substrate/client/hop/src/types.rs (L74-86)
```rust
	/// `MultiSigner` of the account that signed the submission. The runtime pallet
	/// re-verifies the submit signature using this key when the unsigned promotion
	/// extrinsic lands on-chain.
	pub signer: MultiSigner,
	/// The user's `hop_submit` signature over `submit_signing_payload(blake2_256(data),
	/// submit_timestamp)`. Carried along for the runtime to re-verify; "submit implies
	/// consent to promote" is the protocol semantic.
	pub signature: MultiSignature,
	/// Submit-time wall-clock timestamp (ms since unix epoch) bound into the
	/// signing payload. The runtime rejects promotions whose timestamp is too far
	/// from on-chain time, so old `(data, signer, signature)` tuples cannot be
	/// replayed indefinitely.
	pub submit_timestamp: u64,
```

**File:** substrate/client/hop/src/types.rs (L275-283)
```rust
/// Maximum number of recipients allowed per submission.
///
/// Caps the fan-out so that per-entry metadata (both RAM and disk) is bounded
/// and `find_recipient`'s signature-verification scan is bounded.
pub const MAX_RECIPIENTS: u32 = 256;

/// A `Vec<Recipient>` that SCALE-decode rejects if it exceeds `MAX_RECIPIENTS`,
/// enforcing the fan-out cap at the type level instead of via scattered runtime checks.
pub type RecipientVec = BoundedVec<Recipient, ConstU32<MAX_RECIPIENTS>>;
```

**File:** substrate/client/hop/src/types.rs (L322-334)
```rust
/// Compute the 32-byte payload signed at `hop_submit` time.
///
/// The runtime pallet re-derives this exact byte sequence to verify the
/// signature on-chain, so the construction must remain byte-identical to the
/// pallet's `signing_payload(data, submit_timestamp)`:
/// `blake2_256(HOP_SUBMIT_CONTEXT || blake2_256(data) || submit_timestamp.to_le_bytes())`.
pub fn submit_signing_payload(hash: &HopHash, submit_timestamp: u64) -> [u8; 32] {
	let mut buf = [0u8; HOP_SUBMIT_CONTEXT.len() + 32 + 8];
	buf[..HOP_SUBMIT_CONTEXT.len()].copy_from_slice(HOP_SUBMIT_CONTEXT);
	buf[HOP_SUBMIT_CONTEXT.len()..HOP_SUBMIT_CONTEXT.len() + 32].copy_from_slice(hash.as_bytes());
	buf[HOP_SUBMIT_CONTEXT.len() + 32..].copy_from_slice(&submit_timestamp.to_le_bytes());
	blake2_256(&buf)
}
```

**File:** substrate/client/hop/src/promotion.rs (L42-55)
```rust
pub trait HopPromoter: Send + Sync + 'static {
	/// Promote a blob of HOP data to permanent on-chain storage.
	///
	/// `signer`, `signature`, and `submit_timestamp` are the user's `hop_submit`-time
	/// `MultiSigner`, signature, and wall-clock timestamp (ms since unix epoch),
	/// carried into the unsigned promotion extrinsic so the runtime pallet can
	/// verify consent on-chain and bound the signature's validity window.
	fn promote(
		&self,
		data: Vec<u8>,
		signer: MultiSigner,
		signature: MultiSignature,
		submit_timestamp: u64,
	) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
```

**File:** substrate/client/hop/README.md (L17-22)
```markdown
- **Disk-backed** — blobs are written to disk immediately as content-addressed
  files, and metadata is persisted to a `parity-db` key-value store. In-memory
  state is limited to derived counter caches that are rebuilt by iterating
  the metadata column at startup.
- **Content-addressed** — entries are keyed by `blake2_256(data)`; duplicates
  are rejected at submit time.
```

**File:** substrate/client/hop/README.md (L149-163)
```markdown
### `hop_submit(data, recipients, signature, signer, submit_timestamp) -> SubmitResult`

Store a blob for the given list of recipients.

- `data`: raw bytes, must be ≤ `HopRuntimeApi::max_promotion_size()` (the runtime
  cap is authoritative — no separate node-side ceiling).
- `recipients`: up to **256** SCALE-encoded `MultiSigner` values (ed25519,
  sr25519, or ecdsa ephemeral public keys).
- `signature`: SCALE-encoded `MultiSignature` over
  `blake2_256(HOP_SUBMIT_CONTEXT || blake2_256(data) || submit_timestamp.to_le_bytes())`.
- `signer`: SCALE-encoded `MultiSigner` of the submitting account.
- `submit_timestamp`: wall-clock submit time in milliseconds since the Unix
  epoch. Bound into the signed payload; the runtime rejects promotions whose
  timestamp drifts too far from on-chain time, so the same `(data, signer,
  signature)` cannot be replayed indefinitely.
```
