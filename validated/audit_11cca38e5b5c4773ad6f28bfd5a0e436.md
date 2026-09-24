No vulnerability found for this question.

The CVE describes a web-application path-traversal bug: an authenticated file-upload endpoint (`shStaticFilePreUpload`) takes an attacker-controlled `fileName` parameter and writes it to disk without sanitizing `../` sequences, which is possible because that Java service has a runtime file-upload API surface reachable by remote HTTP clients.

Polkadot SDK's runtime (FRAME pallets, XCM executor, contracts/revive) has no equivalent user-facing entry point that takes a filesystem path/filename from a signed extrinsic, contract call, or XCM message and performs file I/O on the node's disk. All the file-path-consuming code I found is either:
- CLI tooling operated by the node operator (not a remote/unprivileged attacker), e.g. `ExportGenesisHeadCommand::run` and `GenerateNodeKeyCmd`/`generate_key` writing to operator-supplied `PathBuf` arguments [1](#0-0) [2](#0-1) , or `export_blocks_cmd.rs` writing to an operator-specified output file [3](#0-2) .
- Build-time/benchmarking/test utilities that run locally under developer control, e.g. `substrate/utils/frame/benchmarking-cli/src/pallet/writer.rs` and `substrate/utils/frame/benchmarking-cli/src/storage/template.rs`, and PVF worker temp-file handling used internally by the node process (not attacker-supplied names) [4](#0-3) .
- Internal client components like `substrate/client/authority-discovery/src/worker/addr_cache.rs`'s `write_to_file`, which uses a fixed cache path rather than any remotely supplied name [5](#0-4) .

None of these are reachable via a signed extrinsic, enabled contract call, or permitted XCM message from an unprivileged remote attacker as required by the analog criteria — they are all either operator-invoked CLI paths or build/test-only code, which the report's methodology explicitly excludes ("Reject tests/mocks/generated/config-only/dependency-only findings, privileged prerequisites..."). There is no FRAME pallet, XCM handler, or contracts/revive dispatchable that accepts a "fileName"-like parameter and performs filesystem writes/reads based on unsanitized attacker input, so there is no demonstrable Polkadot SDK analog to this path-traversal CVE.

### Citations

**File:** cumulus/client/cli/src/lib.rs (L168-189)
```rust
impl ExportGenesisHeadCommand {
	/// Run the export-genesis-head command
	pub fn run<B, C>(&self, client: Arc<C>) -> sc_cli::Result<()>
	where
		B: BlockT,
		C: HeaderBackend<B> + 'static,
	{
		let raw_header = get_raw_genesis_header(client)?;
		let output_buf = if self.raw {
			raw_header
		} else {
			format!("0x{:?}", HexDisplay::from(&raw_header)).into_bytes()
		};

		if let Some(output) = &self.output {
			fs::write(output, output_buf)?;
		} else {
			io::stdout().write_all(&output_buf)?;
		}

		Ok(())
	}
```

**File:** substrate/client/cli/src/commands/generate_node_key.rs (L96-139)
```rust
fn generate_key(
	file: &Option<PathBuf>,
	bin: bool,
	chain_spec_id: Option<&str>,
	base_path: &Option<PathBuf>,
	default_base_path: bool,
	executable_name: Option<&String>,
) -> Result<(), Error> {
	let keypair = ed25519::Keypair::generate();

	let secret = keypair.secret();

	let file_data = if bin {
		secret.as_ref().to_owned()
	} else {
		array_bytes::bytes2hex("", secret).into_bytes()
	};

	match (file, base_path, default_base_path) {
		(Some(file), None, false) => fs::write(file, file_data)?,
		(None, Some(_), false) | (None, None, true) => {
			let network_path = build_network_key_dir_or_default(
				base_path.clone().map(BasePath::new),
				chain_spec_id.unwrap_or_default(),
				executable_name.ok_or(Error::Input("Executable name not provided".into()))?,
			);

			fs::create_dir_all(network_path.as_path())?;

			let key_path = network_path.join(NODE_KEY_ED25519_FILE);
			if key_path.exists() {
				eprintln!("Skip generation, a key already exists in {:?}", key_path);
				return Err(Error::KeyAlreadyExistsInPath(key_path));
			} else {
				eprintln!("Generating key in {:?}", key_path);
				fs::write(key_path, file_data)?
			}
		},
		(None, None, false) => io::stdout().lock().write_all(&file_data)?,
		(_, _, _) => {
			// This should not happen, arguments are marked as mutually exclusive.
			return Err(Error::Input("Mutually exclusive arguments provided".into()));
		},
	}
```

**File:** substrate/client/cli/src/commands/export_blocks_cmd.rs (L65-92)
```rust
impl ExportBlocksCmd {
	/// Run the export-blocks command
	pub async fn run<B, C>(
		&self,
		client: Arc<C>,
		database_config: DatabaseSource,
	) -> error::Result<()>
	where
		B: BlockT,
		C: HeaderBackend<B> + BlockBackend<B> + UsageProvider<B> + 'static,
		<<B::Header as HeaderT>::Number as FromStr>::Err: Debug,
	{
		if let Some(path) = database_config.path() {
			info!("DB path: {}", path.display());
		}

		let from = self.from.as_ref().and_then(|f| f.parse().ok()).unwrap_or(1u32);
		let to = self.to.as_ref().and_then(|t| t.parse().ok());

		let binary = self.binary;

		let file: Box<dyn io::Write> = match &self.output {
			Some(filename) => Box::new(fs::File::create(filename)?),
			None => Box::new(io::stdout()),
		};

		export_blocks(client, file, from.into(), to, binary).await.map_err(Into::into)
	}
```

**File:** polkadot/node/core/pvf/src/prepare/worker_interface.rs (L310-335)
```rust
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

**File:** substrate/client/authority-discovery/src/worker/addr_cache.rs (L109-115)
```rust
fn write_to_file(path: impl AsRef<Path>, contents: &str) -> io::Result<()> {
	let path = path.as_ref();
	let mut file = File::create(path)?;
	file.write_all(contents.as_bytes())?;
	file.flush()?;
	Ok(())
}
```
