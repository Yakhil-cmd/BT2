No vulnerability found for this question.

I searched for a Polkadot SDK analog to CVE-2020-37173 (unauthenticated ID-parameter enumeration leaking sensitive per-user data like password hashes and admin flags) but found no matching pattern that violates a real invariant.

The closest surface areas — `AuthorApi` methods like `author_hasKey`/`author_rotateKeys`/`author_hasSessionKeys` that operate on key material — are gated behind `check_if_safe(ext)` and are unsafe-RPC-restricted, not exposed to arbitrary remote callers by default. [1](#0-0)  Session key registration itself requires a valid ownership proof bound to the signer (`ensure_signed` + `ownership_proof_is_valid`), so there's no unauthenticated path to read or spoof another account's key material. [2](#0-1)  More broadly, on-chain state (balances, nonces, session keys) in FRAME is intentionally public by design via storage/RPC (e.g. `system_accountNextIndex`), so an "information disclosure via ID enumeration" bug class from a traditional web app (like AVideo's `playlistsFromUser.json.php`) does not map onto a violated confidentiality invariant here. [3](#0-2) 

No credible analog with a demonstrable violated invariant, attacker-controlled input, and missing check was identified in scope.

### Citations

**File:** substrate/client/rpc/src/author/mod.rs (L154-189)
```rust
	fn rotate_keys(&self, ext: &Extensions) -> Result<Bytes> {
		check_if_safe(ext)?;

		self.rotate_keys_impl(Vec::new()).map(|k| k.keys)
	}

	fn rotate_keys_with_owner(
		&self,
		ext: &Extensions,
		owner: Bytes,
	) -> Result<GeneratedSessionKeys> {
		check_if_safe(ext)?;

		self.rotate_keys_impl(owner.0)
	}

	fn has_session_keys(&self, ext: &Extensions, session_keys: Bytes) -> Result<bool> {
		check_if_safe(ext)?;

		let best_block_hash = self.client.info().best_hash;
		let keys = self
			.client
			.runtime_api()
			.decode_session_keys(best_block_hash, session_keys.to_vec())
			.map_err(|e| Error::Client(Box::new(e)))?
			.ok_or(Error::InvalidSessionKeys)?;

		Ok(self.keystore.has_keys(&keys))
	}

	fn has_key(&self, ext: &Extensions, public_key: Bytes, key_type: String) -> Result<bool> {
		check_if_safe(ext)?;

		let key_type = key_type.as_str().try_into().map_err(|_| Error::BadKeyType)?;
		Ok(self.keystore.has_keys(&[(public_key.to_vec(), key_type)]))
	}
```

**File:** substrate/frame/session/src/lib.rs (L702-713)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::set_keys())]
		pub fn set_keys(origin: OriginFor<T>, keys: T::Keys, proof: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(
				who.using_encoded(|who| keys.ownership_proof_is_valid(who, &proof)),
				Error::<T>::InvalidProof,
			);

			Self::do_set_keys(&who, keys)?;
			Ok(())
		}
```

**File:** substrate/utils/frame/rpc/system/src/lib.rs (L42-53)
```rust
pub trait SystemApi<BlockHash, AccountId, Nonce> {
	/// Returns the next valid index (aka nonce) for given account.
	///
	/// This method takes into consideration all pending transactions
	/// currently in the pool and if no transactions are found in the pool
	/// it fallbacks to query the index from the runtime (aka. state nonce).
	#[method(name = "system_accountNextIndex", aliases = ["account_nextIndex"])]
	async fn nonce(&self, account: AccountId) -> RpcResult<Nonce>;

	/// Dry run an extrinsic at a given block. Return SCALE encoded ApplyExtrinsicResult.
	#[method(name = "system_dryRun", aliases = ["system_dryRunAt"], with_extensions)]
	async fn dry_run(&self, extrinsic: Bytes, at: Option<BlockHash>) -> RpcResult<Bytes>;
```
