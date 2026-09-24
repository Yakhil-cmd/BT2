No vulnerability found for this question.

This CVE describes a Jenkins CI/CD plugin storing credentials unencrypted in local configuration files, an issue specific to Jenkins' credential management UI and file-based job configs. There is no runtime analog in the Polkadot SDK: no signed extrinsic, contract call, or XCM message path allows an unprivileged attacker to read another party's secrets from a config file. The closest structural matches in the codebase are node-operator-controlled artifacts — the local filesystem keystore [1](#0-0)  and node identity key files [2](#0-1)  — but these are local, operator-owned files on the node operator's own machine, not accessible to a remote unprivileged attacker via any dispatchable, contract call, or XCM message, so they don't satisfy the required "real user entry" criterion of a signed extrinsic, enabled contract deploy/call, or permitted XCM execute/send/transfer.

### Citations

**File:** substrate/client/keystore/src/local.rs (L499-523)
```rust
	/// Insert a new key with anonymous crypto.
	///
	/// Places it into the file system store, if a path is configured.
	fn insert(&self, key_type: KeyTypeId, suri: &str, public: &[u8]) -> Result<()> {
		if let Some(path) = self.key_file_path(public, key_type) {
			Self::write_to_file(path, suri)?;
		}

		Ok(())
	}

	/// Generate a new key.
	///
	/// Places it into the file system store, if a path is configured. Otherwise insert
	/// it into the memory cache only.
	fn generate_by_type<Pair: CorePair>(&mut self, key_type: KeyTypeId) -> Result<Pair> {
		let (pair, phrase, _) = Pair::generate_with_phrase(self.password());
		if let Some(path) = self.key_file_path(pair.public().as_slice(), key_type) {
			Self::write_to_file(path, &phrase)?;
		} else {
			self.insert_ephemeral_pair(&pair, &phrase, key_type);
		}

		Ok(pair)
	}
```

**File:** substrate/client/network/src/config.rs (L401-428)
```rust
/// Load a secret key from a file, if it exists, or generate a
/// new secret key and write it to that file. In either case,
/// the secret key is returned.
fn get_secret<P, F, G, E, W, K>(file: P, parse: F, generate: G, serialize: W) -> io::Result<K>
where
	P: AsRef<Path>,
	F: for<'r> FnOnce(&'r mut [u8]) -> Result<K, E>,
	G: FnOnce() -> K,
	E: Error + Send + Sync + 'static,
	W: Fn(&K) -> Vec<u8>,
{
	std::fs::read(&file)
		.and_then(|mut sk_bytes| {
			parse(&mut sk_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
		})
		.or_else(|e| {
			if e.kind() == io::ErrorKind::NotFound {
				file.as_ref().parent().map_or(Ok(()), fs::create_dir_all)?;
				let sk = generate();
				let mut sk_vec = serialize(&sk);
				write_secret_file(file, &sk_vec)?;
				sk_vec.zeroize();
				Ok(sk)
			} else {
				Err(e)
			}
		})
}
```
