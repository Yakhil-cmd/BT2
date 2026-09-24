No vulnerability found for this question.

After investigating the reachable analog: the Jenkins CVE describes temp files created with default (insecure) OS permissions during multipart file-upload handling, allowing a co-resident local user to read/write them before use. The closest structural pattern in this codebase is the `HopDataPool` off-chain data-relay pool in [1](#0-0)  and the artifact/temp-file handling in the PVF worker interfaces [2](#0-1)  and [3](#0-2) , which all create temporary files using default filesystem permissions (`fs::write`, `File::create`, `tempfile::NamedTempFile`) rather than explicitly restrictive modes.

However, none of these qualify as a valid analog under the required methodology:

- The vulnerability class is fundamentally a **local, co-resident-user file-permission disclosure/TOCTOU issue** — it requires another local OS user/process on the same host to read or tamper with the file before it's moved/consumed. That is a privileged/co-located prerequisite, which the task explicitly excludes ("attacker has no privileged role... no malicious peer/node/validator/collator/relayer").
- None of these code paths are reachable through a signed extrinsic, permitted XCM execute/send/transfer, contract call, or public proof submission — the required entry points. The PVF worker temp-artifact files are internal validator-node compilation caching mechanisms [4](#0-3) , gated by the node's own local filesystem/Landlock sandboxing rather than chain-state logic. The `HopDataPool::insert` blob/meta writer is a client-side storage layer [5](#0-4) , not a runtime pallet dispatchable, so even if reachable by an unprivileged network submitter, any resulting impact is local node information exposure to a co-resident process, not a measurable on-chain loss, unbacked issuance, unauthorized dispatch, or integrity break.
- There is no cross-pallet or runtime state mutation, no fee/asset accounting break, and no way to weaponize this into theft or chain-integrity failure purely through legitimate extrinsic/XCM/contract submission.

Since the bug class cannot be demonstrated through any of the mandated real user entry points and only manifests given an already-privileged local co-resident attacker (excluded by the report's rules), there is no valid Polkadot SDK analog to report.

### Citations

**File:** substrate/client/hop/src/pool.rs (L582-600)
```rust
	/// Atomically write data to a file (write to a unique .tmp path, then rename).
	///
	/// The tmp suffix encodes process id + a per-process atomic counter so two
	/// threads writing the same final path (i.e. same content-addressed hash)
	/// do not race on a shared tmp file. Removes the tmp file on failure so a
	/// failed write never leaves an orphan.
	fn write_atomic(path: &Path, data: &[u8]) -> Result<(), HopError> {
		let suffix = format!("tmp.{}.{}", process::id(), TMP_SEQ.fetch_add(1, Ordering::Relaxed));
		let tmp_path = path.with_extension(suffix);
		if let Err(e) = fs::write(&tmp_path, data) {
			let _ = fs::remove_file(&tmp_path);
			return Err(e.into());
		}
		if let Err(e) = fs::rename(&tmp_path, path) {
			let _ = fs::remove_file(&tmp_path);
			return Err(e.into());
		}
		Ok(())
	}
```

**File:** substrate/client/hop/src/pool.rs (L605-676)
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
```

**File:** polkadot/node/core/pvf/src/prepare/worker_interface.rs (L305-335)
```rust
/// Create a temporary file for an artifact in the worker cache, execute the given future/closure
/// passing the file path in, and clean up the worker cache.
///
/// Failure to clean up the worker cache results in an error - leaving any files here could be a
/// security issue, and we should shut down the worker. This should be very rare.
async fn with_worker_dir_setup<F, Fut>(
	worker_dir: WorkerDir,
	stream: UnixStream,
	pid: u32,
	f: F,
) -> Outcome
where
	Fut: futures::Future<Output = Outcome>,
	F: FnOnce(PathBuf, UnixStream, WorkerDir) -> Fut,
{
	// Create the tmp file here so that the child doesn't need any file creation rights. This will
	// be cleared at the end of this function.
	let tmp_file = worker_dir::prepare_tmp_artifact(worker_dir.path());
	if let Err(err) = tokio::fs::File::create(&tmp_file).await {
		gum::warn!(
			target: LOG_TARGET,
			worker_pid = %pid,
			?worker_dir,
			"failed to create a temp file for the artifact: {:?}",
			err,
		);
		return Outcome::CreateTmpFileErr {
			worker: IdleWorker { stream, pid, worker_dir },
			err: format!("{:?}", err),
		};
	};
```

**File:** polkadot/node/core/pvf/src/worker_interface.rs (L120-158)
```rust
async fn with_transient_socket_path<T, F, Fut>(debug_id: &'static str, f: F) -> Result<T, SpawnErr>
where
	F: FnOnce(&Path) -> Fut,
	Fut: futures::Future<Output = Result<T, SpawnErr>> + 'static,
{
	/// Returns a path under [`std::env::temp_dir`]. The path name will start with the given prefix.
	///
	/// There is only a certain number of retries. If exceeded this function will give up and return
	/// an error.
	pub async fn tmppath(prefix: &str) -> io::Result<PathBuf> {
		fn make_tmppath(prefix: &str, dir: &Path) -> PathBuf {
			use rand::distributions::Alphanumeric;

			const DISCRIMINATOR_LEN: usize = 10;

			let mut buf = Vec::with_capacity(prefix.len() + DISCRIMINATOR_LEN);
			buf.extend(prefix.as_bytes());
			buf.extend(rand::thread_rng().sample_iter(&Alphanumeric).take(DISCRIMINATOR_LEN));

			let s = std::str::from_utf8(&buf)
				.expect("the string is collected from a valid utf-8 sequence; qed");

			let mut path = dir.to_owned();
			path.push(s);
			path
		}

		const NUM_RETRIES: usize = 50;

		let dir = std::env::temp_dir();
		for _ in 0..NUM_RETRIES {
			let tmp_path = make_tmppath(prefix, &dir);
			if !tmp_path.exists() {
				return Ok(tmp_path);
			}
		}

		Err(io::Error::new(io::ErrorKind::Other, "failed to create a temporary path"))
	}
```
