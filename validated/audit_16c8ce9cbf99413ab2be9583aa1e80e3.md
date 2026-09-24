### Title
`hop_submit` signature does not bind the `recipients` list, allowing replay of another account's stale submit-signature to redirect a Hand-Off Protocol entry to attacker-controlled recipients while spending the victim account's authorization and quota - (File: `substrate/client/hop/src/rpc.rs`)

### Summary
`sc-hop`'s `hop_submit` RPC verifies a submitter's `MultiSignature` over `blake2_256(HOP_SUBMIT_CONTEXT || blake2_256(data) || submit_timestamp)` [1](#0-0)  but the `recipients` list passed to `HopDataPool::insert` is never part of that signed payload [2](#0-1) . This mirrors the OpenClaw bug class: an attacker-controlled field (`recipients`, analogous to OpenClaw's `platform`/`deviceFamily`) is accepted from the caller and used to determine who is authorized to later claim/control the entry, without being bound into the cryptographic proof that established the submitter's identity/authorization.

### Finding Description
`do_submit` performs, in order: decode inputs, size check, `can_account_promote(account_id, data_len)` authorization check keyed off the `signer` field, then finally signature verification of `submit_payload` over only `hash(data) || submit_timestamp` [3](#0-2) . The `recipients` decoded earlier is passed straight into `pool.insert(...)` without any cryptographic tie to the signer's signature [4](#0-3) .

Because entries are content-addressed by `blake2_256(data)` and duplicates are rejected only while the original entry still exists [5](#0-4) , once an original entry is removed (all recipients acked, promoted, or expired) the hash slot becomes free again. `HopEntryMeta` on the wire/off-chain, and once promoted, on-chain (`create_promotion_extrinsic` carries `data`, `signer`, `signature`, `submit_timestamp` verbatim) [6](#0-5) , exposes the full `(data, signer, signature, submit_timestamp)` tuple permanently and publicly.

Any observer who later extracts that tuple (from a promoted extrinsic, or any other channel that surfaced it) can call `hop_submit` again with the **same** `data`, `signer`, `signature`, `submit_timestamp`, but with a **new `recipients` list naming keys the attacker controls**. The replayed signature still verifies (it only covers `data`+`timestamp`), `can_account_promote` is evaluated against the *original* signer's `account_id` — an account the attacker never controlled and whose key the attacker never needed — and `sender_id` in the resulting `HopEntryMeta` is set to that same victim account for quota accounting [7](#0-6) [8](#0-7) . The attacker's own `recipients` keys can then `hop_claim`/`hop_ack` the re-inserted entry.

This is the direct analog of the OpenClaw flaw: `platform`/`deviceFamily` (policy-relevant metadata) was accepted from the client and not bound into the device-auth signature, so it could be freely substituted on reconnect to broaden the caller's effective privilege. Here `recipients` (control-relevant metadata determining who may later claim/ack the entry) is accepted from the RPC caller and not bound into the `hop_submit` signature, so it can be freely substituted while the request still authenticates as, and consumes quota belonging to, the original signer.

### Impact Explanation
An attacker who never held the victim's private key can:
- Consume the victim account's `can_account_promote`/per-account rate-limit and `--hop-max-user-size` quota indefinitely by repeatedly replaying one captured `(data, signer, signature, submit_timestamp)` tuple with new `recipients`, once the corresponding entry has left the pool.
- Insert entries attributed to (and billed against) an account they do not control, and designate themselves as the only recipient, allowing them to `hop_claim`/`hop_ack` data under someone else's submitted authorization.

This does not directly mint funds or dispatch a privileged call, but it is an authorization/identity-binding failure at a real, permissionless JSON-RPC entry point (`hop_submit`/`hop_claim`/`hop_ack`), letting an attacker spend another account's server-side authorization allowance and quota without their key — a genuine violation of the "signer implies consent" invariant the crate's own documentation asserts (`substrate/client/hop/src/types.rs:78-80`). Severity is best characterized as Medium: it is a resource/authorization-spoofing issue rather than fund theft, unbacked issuance, or unauthorized on-chain dispatch, since the promoted `data` content itself is already public once on-chain.

### Likelihood Explanation
Reachability requires only: (1) HOP enabled on a node (`--enable-hop`), (2) any prior legitimate `hop_submit` whose entry has since left the pool (acked, promoted, or expired), and (3) the attacker obtaining the `(data, signer, signature, submit_timestamp)` tuple — trivially satisfied once an entry is promoted on-chain, since `create_promotion_extrinsic` embeds all four fields verbatim into a permanently public extrinsic. No governance, validator, or stolen-key assumption is needed; the attacker only replays an already-valid signature, never forging one. I could not confirm from the available code whether `do_submit` enforces any timestamp-freshness check at the RPC layer itself (the README's staleness guard is described as a runtime/on-chain check at promotion time, not necessarily an RPC-layer check on `hop_submit`); if such a freshness check does exist in `do_submit` and rejects stale `submit_timestamp` values outright, the replay window would be narrower (bounded by the tolerance window) but not eliminated, since the attack only needs a recent enough entry to have already cycled out of the pool.

### Recommendation
Bind `recipients` (and any other pool-insert-affecting fields) into the `hop_submit` signing payload, e.g. `blake2_256(HOP_SUBMIT_CONTEXT || blake2_256(data) || submit_timestamp || blake2_256(encode(recipients)))`, so a valid submit signature authorizes exactly one fixed recipient set. Additionally, enforce a submit-timestamp freshness window directly in `do_submit` (not only at on-chain promotion time) so a captured tuple cannot be replayed into the ephemeral pool long after the fact.

### Proof of Concept
Not executed against a running node; this is a source-level analysis based on `substrate/client/hop/src/rpc.rs`, `substrate/client/hop/src/pool.rs`, `substrate/client/hop/src/types.rs`, and `substrate/primitives/hop/src/lib.rs`. A minimal reproduction would: (1) submit `data` via `hop_submit` as account A with `recipients = [R1]`; (2) wait for the entry to be promoted or fully acked/expired so it leaves the pool; (3) extract `(data, signer=A, signature, submit_timestamp)` from the promoted extrinsic or captured request; (4) call `hop_submit` again with the same four values but `recipients = [R2]` (attacker-controlled); (5) observe the call succeeds, `can_account_promote` was evaluated against A, and `hop_claim`/`hop_ack` with R2's key retrieves/acks the entry. I was not able to run this end-to-end in this session; execution should be validated against `substrate/client/hop`'s existing test harness (e.g. `pool.rs` unit tests already exercise `insert`/`claim`/`ack` and could be extended with a "replay with different recipients" case).

### Citations

**File:** substrate/client/hop/src/rpc.rs (L194-262)
```rust
	fn do_submit(
		&self,
		data: Bytes,
		recipients: Vec<Bytes>,
		signature: Bytes,
		signer: Bytes,
		submit_timestamp: u64,
	) -> Result<SubmitResult, HopError> {
		let recipient_keys: RecipientVec = recipients
			.into_iter()
			.map(|r| {
				MultiSigner::decode(&mut &r.0[..])
					.map(|signer| Recipient { signer, claimed: false })
					.map_err(|_| HopError::InvalidRecipientKey)
			})
			.collect::<Result<Vec<_>, _>>()?
			.try_into()
			.map_err(|v: Vec<Recipient>| HopError::TooManyRecipients {
				provided: v.len(),
				limit: MAX_RECIPIENTS as usize,
			})?;

		let signer =
			MultiSigner::decode(&mut &signer.0[..]).map_err(|_| HopError::InvalidSigner)?;
		let multi_sig = MultiSignature::decode(&mut &signature.0[..])
			.map_err(|_| HopError::InvalidSignature)?;

		let chain_info = self.client.info();
		let best_hash = chain_info.best_hash;

		let data_len = data.0.len();

		// Reject oversized payloads before the per-account authorization lookup so
		// a flood of too-big submits cannot force runtime state reads. The cap is
		// the runtime-declared `max_promotion_size`; the runtime is authoritative.
		let runtime_max = runtime_api::max_promotion_size::<Block, _>(&*self.client, best_hash)
			.map_err(HopError::from)?;
		if data_len > runtime_max as usize {
			return Err(HopError::DataTooLarge(data_len, runtime_max).into());
		}

		// Check authorization before verifying the signature: a flood of unauthorized
		// requests must not force a signature verification per submit.
		// `can_account_promote` returns false for any reason the runtime rejects:
		// unauthorized account or exhausted per-account quota.
		let account_id: AccountId32 = signer.clone().into_account();
		let authorized = runtime_api::can_account_promote::<Block, _>(
			&*self.client,
			best_hash,
			account_id.clone(),
			data_len as u32,
		)
		.map_err(HopError::from)?;
		if !authorized {
			return Err(HopError::NotAuthorized);
		}

		// Domain-separated payload so a submit signature cannot be replayed as claim/ack,
		// and bound to `submit_timestamp` so an old signature can't be replayed long
		// after the fact (the runtime enforces a tolerance window on the timestamp).
		let hash = H256(blake2_256(&data.0));
		let submit_payload = submit_signing_payload(&hash, submit_timestamp);
		if !multi_sig.verify(&submit_payload[..], &account_id) {
			return Err(HopError::InvalidSignature);
		}

		let sender_id: [u8; 32] = account_id.into();
		self.pool
			.insert(data.0, recipient_keys, sender_id, signer, multi_sig, submit_timestamp)?;
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

**File:** substrate/primitives/hop/src/lib.rs (L47-63)
```rust
		/// Construct an unsigned promotion extrinsic carrying the user's submit-time
		/// (in milliseconds from the Unix epoch), signer, signature, and timestamp
		/// so the runtime pallet can verify consent on-chain.
		///
		/// `submit_timestamp` is bound into the signed payload. Implementing
		/// runtimes **must** reject promotions whose timestamp is outside a
		/// tolerance window around the current on-chain clock — otherwise the
		/// same `(data, signer, signature)` tuple can be replayed indefinitely
		/// from the collator's persisted metadata. The width of the window is a
		/// runtime policy decision (clock skew + max acceptable promotion
		/// latency); a few hours is a reasonable upper bound.
		fn create_promotion_extrinsic(
			data: alloc::vec::Vec<u8>,
			signer: sp_runtime::MultiSigner,
			signature: sp_runtime::MultiSignature,
			submit_timestamp: u64,
		) -> Block::Extrinsic;
```

**File:** substrate/client/hop/src/types.rs (L70-86)
```rust
	/// Account ID of the sender who submitted this entry.
	pub sender_id: SenderId,
	/// Whether this entry has been promoted to permanent on-chain storage.
	pub promoted: bool,
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
