No vulnerability found for this question.

The reported bug class—path traversal via attacker-controlled filenames used in filesystem writes (backslash/period sequences escaping a base directory)—has no meaningful analog in Polkadot SDK's production runtime code. All file-write call sites found in the codebase are either:

- Node-operator CLI commands (`generate-node-key`, `export-blocks`, `export-genesis-wasm`) where paths come from local command-line arguments, not from network/extrinsic input [1](#0-0) [2](#0-1) [3](#0-2) 
- Build-time tooling and benchmarking utilities (fixtures builder, storage/pallet benchmark writers) that run offline during compilation/dev workflows, never during on-chain execution [4](#0-3) [5](#0-4) 
- Network key-file storage in `substrate/client/network/src/config.rs`, again node-local configuration, not attacker-influenced [6](#0-5) 

None of these are reachable through a signed extrinsic, contract call, or XCM message dispatched by an unprivileged attacker. FRAME's runtime state transition model stores all pallet data in the on-chain trie/storage abstraction, not on a node's local filesystem, so there is no code path where untrusted transaction/XCM payload content is used to construct a filesystem path for writing "custom assets" or any other user data. This eliminates the core precondition of the report (attacker-controlled path segments reaching an unguarded `fs::write`/`File::create` call in a reachable, unprivileged network entry point).

### Citations

**File:** substrate/client/cli/src/commands/generate_node_key.rs (L96-132)
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
```

**File:** substrate/client/cli/src/commands/export_blocks_cmd.rs (L86-91)
```rust
		let file: Box<dyn io::Write> = match &self.output {
			Some(filename) => Box::new(fs::File::create(filename)?),
			None => Box::new(io::stdout()),
		};

		export_blocks(client, file, from.into(), to, binary).await.map_err(Into::into)
```

**File:** cumulus/client/cli/src/lib.rs (L221-238)
```rust
impl ExportGenesisWasmCommand {
	/// Run the export-genesis-wasm command
	pub fn run(&self, chain_spec: &dyn ChainSpec) -> sc_cli::Result<()> {
		let raw_wasm_blob = extract_genesis_wasm(chain_spec)?;
		let output_buf = if self.raw {
			raw_wasm_blob
		} else {
			format!("0x{:?}", HexDisplay::from(&raw_wasm_blob)).into_bytes()
		};

		if let Some(output) = &self.output {
			fs::write(output, output_buf)?;
		} else {
			io::stdout().write_all(&output_buf)?;
		}

		Ok(())
	}
```

**File:** substrate/frame/revive/fixtures/src/builder.rs (L352-368)
```rust
pub fn post_process(input_path: &Path, output_path: &Path) -> Result<()> {
	let strip = env::var(OVERRIDE_STRIP_ENV_VAR).map_or(false, |value| value == "1");
	let optimize = env::var(OVERRIDE_OPTIMIZE_ENV_VAR).map_or(true, |value| value == "1");

	let mut config = polkavm_linker::Config::default();
	config.set_strip(strip);
	config.set_optimize(optimize);
	let orig = fs::read(input_path).with_context(|| format!("Failed to read {input_path:?}"))?;
	let linked = polkavm_linker::program_from_elf(
		config,
		polkavm_linker::TargetInstructionSet::ReviveV1,
		orig.as_ref(),
	)
	.map_err(|err| anyhow::format_err!("Failed to link polkavm program: {}", err))?;
	fs::write(output_path, linked).with_context(|| format!("Failed to write {output_path:?}"))?;
	Ok(())
}
```

**File:** substrate/utils/frame/benchmarking-cli/src/pallet/writer.rs (L462-504)
```rust
	let mut created_files = Vec::new();

	for ((pallet, instance), results) in all_results.iter() {
		let mut file_path = path.clone();
		// If a user only specified a directory...
		if file_path.is_dir() {
			// Start with "path/to/pallet_name".
			let mut file_name = pallet.clone();
			// Check if there might be multiple instances benchmarked.
			if all_results.keys().any(|(p, i)| p == pallet && i != instance) {
				// Append "_instance_name".
				file_name = format!("{}_{}", file_name, instance.to_snake_case());
			}
			// "mod::pallet_name.rs" becomes "mod_pallet_name.rs".
			file_name = file_name.replace("::", "_");
			// Some old runtimes have a bug with the pallet and instance name containing a space
			file_name = file_name.replace(" ", "");
			file_path.push(file_name);
			file_path.set_extension("rs");
		}

		let hbs_data = TemplateData {
			args: args.clone(),
			date: date.clone(),
			hostname: cmd.hostinfo_params.hostname(),
			cpuname: cmd.hostinfo_params.cpuname(),
			version: VERSION.to_string(),
			pallet: pallet.to_string(),
			instance: instance.to_string(),
			header: header_text.clone(),
			cmd: cmd_data.clone(),
			benchmarks: results.clone(),
		};

		let mut output_file = fs::File::create(&file_path).map_err(|e| {
			format!("Could not write weight file to: {:?}. Error: {:?}", &file_path, e)
		})?;
		handlebars
			.render_template_to_write(&template, &hbs_data, &mut output_file)
			.map_err(|e| io_error(&e.to_string()))?;
		println!("Created file: {:?}", &file_path);
		created_files.push(file_path);
	}
```

**File:** substrate/client/network/src/config.rs (L431-447)
```rust
pub(super) fn write_secret_file<P>(path: P, sk_bytes: &[u8]) -> io::Result<()>
where
	P: AsRef<Path>,
{
	let mut file = open_secret_file(&path)?;
	file.write_all(sk_bytes)
}

/// Opens a file containing a secret key in write mode.
#[cfg(unix)]
fn open_secret_file<P>(path: P) -> io::Result<fs::File>
where
	P: AsRef<Path>,
{
	use std::os::unix::fs::OpenOptionsExt;
	fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}
```
