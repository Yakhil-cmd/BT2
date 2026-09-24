I found a direct structural analog in this codebase's custom HOP (Hand-Off Protocol) client.

### Title
`hop_submit` signature omits the `recipients` list, letting an unauthenticated caller redirect private data to arbitrary keys - (File: substrate/client/hop/src/rpc.rs)

### Summary
The `hop_submit` RPC method accepts `data`, `recipients`, `signature`, `signer`, and `submit_timestamp` as independent, unauthenticated parameters. The `signature` is only verified against `submit_signing_payload(hash, submit_timestamp)`, i.e. `blake2_256(HOP_SUBMIT_CONTEXT || blake2_256(data) || submit_timestamp.to_le_bytes())` [1](#0-0) . The `recipients` argument — which determines who can later decrypt/claim the stored blob — is never part of that signed payload, exactly mirroring the reported Nexus bug where `moduleType` was accepted from the caller but excluded from the signed hash `_getEnableModeDataHash()`.

### Finding Description
`HopApi::submit` is a public, unauthenticated RPC entry point: any client with access to the node's RPC (not a validator/collator/relayer/governance role) can call it [2](#0-1) . `do_submit` decodes the `recipients` list, the `signer`, and the `signature`, checks size and authorization, and only then verifies the signature: `multi_sig.verify(&submit_payload[..], &account_id)` where `submit_payload = submit_signing_payload(&hash, submit_timestamp)` [3](#0-2) . The signed payload is derived solely from the `data` hash and `submit_timestamp` — `recipients` is entirely outside the signature's scope, per the doc comment: "The user's `hop_submit` signature over `submit_signing_payload(blake2_256(data), submit_timestamp)`" [4](#0-3) .

Once the signature check passes, `insert()` stores whatever `recipients` value was supplied in the RPC call into `HopEntryMeta` alongside the (data, signer, signature) tuple [5](#0-4) . `hop_claim`/`hop_ack` then trust `meta.recipients` to authorize retrieval, verifying only that a caller's ephemeral key matches an entry in that list [6](#0-5) . Because `recipients` was never bound into what the signer actually signed, a party who observes a valid `(data, signer, signature, submit_timestamp)` tuple — e.g. a network intermediary, or simply anyone who is handed those values before pool insertion completes — can resubmit the identical signature with a **different `recipients` list**, redirecting who is authorized to read the private blob. This is structurally identical to the Nexus flaw: the signature attests to "I approve submitting this data at this time," but the actually-installed effect (`recipients` for HOP, `moduleType` for Nexus) is a separate, unsigned, attacker-suppliable field consumed right after the signature check.

### Impact Explanation
HOP is a hand-off channel for otherwise off-chain-relayed private data (recipients are ephemeral keypairs used for confidential retrieval per the README) [7](#0-6) . If an attacker can front-run or replay a captured `(data, signer, signature, submit_timestamp)` tuple with a substituted `recipients` field, they can claim data intended for someone else, or lock out the intended recipients from ever claiming/acking (since the entry's `recipients` set now differs from what the signer intended), causing a confidentiality break and/or availability break for HOP-based flows. Since `HopDataPool::insert` is idempotent per content-hash (`DuplicateEntry` on collision) and does not itself reject a first successful insert, the attacker only needs to win the race to submit before the legitimate submission lands [8](#0-7) .

### Likelihood Explanation
Medium: it requires the attacker to obtain a valid `(data, signer, signature, submit_timestamp)` tuple before/without the legitimate submission being finalized (e.g., by observing it in transit to the RPC, or if the signer's tooling exposes the signature before submission), and to win a race against the genuine submit. It does not require any privileged role, key theft, or malicious validator/collator — it is exploitable by an ordinary RPC caller who obtains a copy of the signed tuple, which is the same "attacker has no privileged role" premise as the reported Nexus bug.

### Recommendation
Bind `recipients` (or at minimum its hash) into `submit_signing_payload` / `HOP_SUBMIT_CONTEXT`, analogous to including `moduleType` in `_getEnableModeDataHash()`: e.g. `blake2_256(HOP_SUBMIT_CONTEXT || blake2_256(data) || blake2_256(recipients.encode()) || submit_timestamp.to_le_bytes())`. Then re-verify this expanded payload both in `do_submit` (`substrate/client/hop/src/rpc.rs`) and in the runtime pallet that re-verifies the signature on-chain during promotion, so the signer's consent unambiguously covers who is authorized to claim the data.

### Proof of Concept
Not executed against a live network, per instructions. Code-level trace performed instead:
1. `submit_signing_payload` construction confirmed to exclude `recipients` [9](#0-8) .
2. `do_submit` confirmed to decode `recipients` independently of, and prior to, signature verification, with no cross-binding [10](#0-9) .
3. `HopDataPool::insert` confirmed to persist the caller-supplied `recipients` as the sole authorization list for later `claim`/`ack` [11](#0-10) .

I did not run an integration test reproducing the race/replay end-to-end (no filesystem/RPC harness execution available in this session); this would need a Devin session with tool access to instantiate `HopRpcServer`/`HopDataPool` and demonstrate the signature accepted with a swapped `recipients` argument. The static trace above establishes the missing-binding root cause with file:line evidence but does not constitute an executed PoC.

### Citations

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

**File:** substrate/client/hop/src/pool.rs (L605-691)
```rust
	pub fn insert(
		&self,
		data: Vec<u8>,
		recipients: RecipientVec,
		sender_id: SenderId,
		signer: MultiSigner,
		signature: MultiSignature,
		submit_timestamp: u64,
	) -> Result<HopHash, HopError> {
		if recipients.is_empty() {
			return Err(HopError::NoRecipients);
		}
		let unique: BTreeSet<&MultiSigner> = recipients.iter().map(|r| &r.signer).collect();
		if unique.len() != recipients.len() {
			return Err(HopError::DuplicateRecipient);
		}

		if data.is_empty() {
			return Err(HopError::EmptyData);
		}

		let data_len = data.len() as u64;

		// Total accounted size includes bounded per-recipient metadata overhead so
		// a submitter cannot inflate memory via large recipient lists while the
		// capacity counter only tracks `data.len()`. Charge the rate limiter the
		// same accounted size, otherwise a 1-byte payload with 256 recipients
		// would cost ~10 KiB of pool capacity while only spending 1 byte of
		// bandwidth tokens — making the bandwidth dimension non-functional for
		// fan-out-heavy entries.
		let accounted = entry_accounted_size(data_len, recipients.len());

		// Rejected requests never reserve capacity — check before any atomic bump.
		if let Err(retry_after_secs) = self.rate_limiter.check(&sender_id, accounted) {
			return Err(HopError::RateLimited { retry_after_secs });
		}

		let previous_size = self.current_size.fetch_add(accounted, Ordering::Relaxed);
		if previous_size.saturating_add(accounted) > self.max_size {
			self.current_size.fetch_sub(accounted, Ordering::Relaxed);
			return Err(HopError::PoolFull(previous_size, self.max_size));
		}

		if let Err(e) = self.charge_user(&sender_id, accounted) {
			self.current_size.fetch_sub(accounted, Ordering::Relaxed);
			return Err(e);
		}

		let hash = H256(blake2_256(&data));

		// Best-effort duplicate check; authoritative check happens under rmw_lock.
		match self.fetch_meta(&hash) {
			Ok(Some(_)) => {
				self.release_user_quota(&sender_id, accounted);
				self.current_size.fetch_sub(accounted, Ordering::Relaxed);
				return Err(HopError::DuplicateEntry);
			},
			Ok(None) => (),
			Err(e) => {
				self.release_user_quota(&sender_id, accounted);
				self.current_size.fetch_sub(accounted, Ordering::Relaxed);
				return Err(e);
			},
		}

		// Blob first; an orphan from a crash before commit is reaped on next startup.
		let blob_path = self.blob_path(&hash);
		if let Err(e) = Self::write_atomic(&blob_path, &data) {
			self.release_user_quota(&sender_id, accounted);
			self.current_size.fetch_sub(accounted, Ordering::Relaxed);
			return Err(e);
		}

		let expires_at = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs()
			.saturating_add(self.retention_secs);
		let meta = HopEntryMeta::new(
			data_len,
			expires_at,
			recipients,
			sender_id,
			signer,
			signature,
			submit_timestamp,
		);
```

**File:** substrate/client/hop/src/pool.rs (L862-881)
```rust
	/// Decode `signature` and return the index of the matching recipient in
	/// `meta.recipients`. `context` is the operation's domain separator (claim
	/// / ack). Returning an index keeps a single implementation for both
	/// shared- and exclusive-borrow callers (`meta.recipients[idx]` works in
	/// either case).
	fn find_recipient_idx(
		meta: &HopEntryMeta,
		hash: &HopHash,
		signature: &[u8],
		context: &[u8],
	) -> Result<usize, HopError> {
		let multi_sig =
			MultiSignature::decode(&mut &signature[..]).map_err(|_| HopError::InvalidSignature)?;
		let payload = signing_payload(context, hash);

		meta.recipients
			.iter()
			.position(|r| multi_sig.verify(&payload[..], &r.signer.clone().into_account()))
			.ok_or(HopError::NotRecipient)
	}
```

**File:** substrate/client/hop/README.md (L151-165)
```markdown
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

Submit fails with:
```
