No vulnerability found for this question.

The STIGQter report describes a desktop GUI application vulnerability: an attacker crafts a malicious `.stigqter` project file, the victim opens it, and clicking "Export HTML" causes arbitrary file write leading to local code execution. This bug class requires a local file-open + export workflow with a human victim explicitly triggering a client-side action on attacker-supplied project data.

I searched `Ellentat/polkadot-sdk--012` for analogous file-write patterns reachable through a genuine attacker entry point (signed extrinsic, contract call, XCM message, or public proof submission). All file-write ("export") code paths found are CLI-only, operator-invoked commands run locally by the node operator with command-line arguments they control themselves — not remote/attacker-controlled inputs:

- `substrate/client/cli/src/commands/export_blocks_cmd.rs` — `ExportBlocksCmd::run` writes to an operator-supplied `--output` path [1](#0-0) 
- `substrate/client/cli/src/commands/export_chain_spec_cmd.rs` — `ExportChainSpecCmd::run` writes chain spec JSON to an operator-supplied path [2](#0-1) 
- `cumulus/client/cli/src/lib.rs` — `ExportGenesisHeadCommand`/`ExportGenesisWasmCommand::run` write to operator-supplied output paths [3](#0-2) 
- `cumulus/client/consensus/aura/src/lib.rs` — `export_pov_to_path` writes PoV files to a collator-operator-configured directory, not attacker input [4](#0-3) 

None of these are reachable via a signed extrinsic, enabled contract deploy/call, permitted XCM execute/send, or public proof submission — the required attacker entry point per the review method is absent. There is no runtime pallet, contract, or XCM handler in this codebase that opens an attacker-supplied file/message and then performs a filesystem write to an attacker-influenced path or content as a consequence of untrusted on-chain input; the FRAME/runtime execution model has no "open project file, click export" client workflow analogous to STIGQter's Qt-based Export HTML feature. This bug class does not have a demonstrable analog in the Polkadot SDK's runtime/extrinsic/XCM attack surface.

### Citations

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

**File:** substrate/client/cli/src/commands/export_chain_spec_cmd.rs (L56-67)
```rust
impl ExportChainSpecCmd {
	/// Run the export-chain-spec command
	pub fn run(&self, spec: Box<dyn ChainSpec>) -> Result<()> {
		let json = chain_ops::build_spec(spec.as_ref(), self.raw)?;
		if let Some(ref path) = self.output {
			fs::write(path, json)?;
			println!("Exported chain spec to {}", path.display());
		} else {
			io::stdout().write_all(json.as_bytes()).map_err(|e| format!("{}", e))?;
		}
		Ok(())
	}
```

**File:** cumulus/client/cli/src/lib.rs (L168-238)
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
}

impl sc_cli::CliConfiguration for ExportGenesisHeadCommand {
	fn shared_params(&self) -> &sc_cli::SharedParams {
		&self.shared_params
	}

	fn base_path(&self) -> sc_cli::Result<Option<BasePath>> {
		// As we are just exporting the genesis wasm a tmp database is enough.
		//
		// As otherwise we may "pollute" the global base path.
		Ok(Some(BasePath::new_temp_dir()?))
	}
}

/// Command for exporting the genesis wasm file.
#[derive(Debug, clap::Parser)]
pub struct ExportGenesisWasmCommand {
	/// Output file name or stdout if unspecified.
	#[arg()]
	pub output: Option<PathBuf>,

	/// Write output in binary. Default is to write in hex.
	#[arg(short, long)]
	pub raw: bool,

	#[allow(missing_docs)]
	#[command(flatten)]
	pub shared_params: sc_cli::SharedParams,
}

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

**File:** cumulus/client/consensus/aura/src/lib.rs (L53-84)
```rust
pub(crate) fn export_pov_to_path<Block: BlockT>(
	path: PathBuf,
	pov: PoV,
	block_hash: Block::Hash,
	block_number: NumberFor<Block>,
	parent_header: Block::Header,
	relay_parent_storage_root: RHash,
	relay_parent_number: RBlockNumber,
	max_pov_size: u32,
) {
	if let Err(error) = fs::create_dir_all(&path) {
		tracing::error!(target: LOG_TARGET, %error, path = %path.display(), "Failed to create PoV export directory");
		return;
	}

	let mut file = match File::create(path.join(format!("{block_hash:?}_{block_number}.pov"))) {
		Ok(f) => f,
		Err(error) => {
			tracing::error!(target: LOG_TARGET, %error, "Failed to export PoV.");
			return;
		},
	};

	pov.encode_to(&mut file);
	PersistedValidationData {
		parent_head: HeadData(parent_header.encode()),
		relay_parent_number,
		relay_parent_storage_root,
		max_pov_size,
	}
	.encode_to(&mut file);
}
```
