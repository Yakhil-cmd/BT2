No vulnerability found for this question.

The CVE describes a web UI access-control flaw where GitLab exposed a CI/CD secret token to unauthorized project maintainers through the browser interface — a pure application-layer information disclosure bug tied to GitLab's own UI rendering logic, not a blockchain state-transition or consensus invariant. Searching the Polkadot SDK for an analogous "secret leaked to unauthorized viewer" pattern only surfaced legitimate, expected secret-handling code: CLI tools that intentionally print seeds/keys to their own invoker (`substrate/client/cli/src/commands/utils.rs`), local keystore file storage (`substrate/client/keystore/src/local.rs`), node identity key files (`substrate/client/network/src/config.rs`), and the statement-store's own encryption tests (`substrate/client/statement-store/src/lib.rs`) — none of which involve a runtime path reachable by an unprivileged signed extrinsic, XCM message, or contract call that discloses another party's secret to an unauthorized third party. [1](#0-0) [2](#0-1) [3](#0-2) 

There is no FRAME pallet, XCM executor path, or pallet-contracts/revive boundary in this codebase that stores a third-party's authentication credential (analogous to a CI token) and then exposes it via a runtime query or UI-equivalent (RPC/event/storage read) to an unauthorized party without an explicit authorization check — the closest constructs (keystore, node identity secrets, subkey CLI output, encrypted statements) are all locally-scoped secrets under the control of the party generating/holding them, not secrets belonging to one user that leak to a different, unauthorized user through a permissioned entry point. Without a genuine cross-user credential-leak pathway reachable through a signed extrinsic, contract call, or XCM message, this CVE class does not have a demonstrable analog in the current codebase.

### Citations

**File:** substrate/client/cli/src/commands/utils.rs (L66-96)
```rust
pub fn print_from_uri<Pair>(
	uri: &str,
	password: Option<SecretString>,
	network_override: Option<Ss58AddressFormat>,
	output: OutputType,
) where
	Pair: sp_core::Pair,
	Pair::Public: Into<MultiSigner>,
{
	let password = password.as_ref().map(|s| s.expose_secret().as_str());
	let network_id = String::from(unwrap_or_default_ss58_version(network_override));
	if let Ok((pair, seed)) = Pair::from_phrase(uri, password) {
		let public_key = pair.public();
		let network_override = unwrap_or_default_ss58_version(network_override);

		match output {
			OutputType::Json => {
				let json = json!({
					"secretPhrase": uri,
					"networkId": network_id,
					"secretSeed": format_seed::<Pair>(seed),
					"publicKey": format_public_key::<Pair>(public_key.clone()),
					"ss58PublicKey": public_key.to_ss58check_with_version(network_override),
					"accountId": format_account_id::<Pair>(public_key),
					"ss58Address": pair.public().into().into_account().to_ss58check_with_version(network_override),
				});
				println!(
					"{}",
					serde_json::to_string_pretty(&json).expect("Json pretty print failed")
				);
			},
```

**File:** substrate/client/keystore/src/local.rs (L459-468)
```rust
impl KeystoreInner {
	/// Open the store at the given path.
	///
	/// Optionally takes a password that will be used to encrypt/decrypt the keys.
	fn open<T: Into<PathBuf>>(path: T, password: Option<SecretString>) -> Result<Self> {
		let path = path.into();
		fs::create_dir_all(&path)?;

		Ok(Self { path: Some(path), additional: HashMap::new(), password })
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
