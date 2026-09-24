No vulnerability found for this question.

The CVE-2018-1000175 pattern requires an attacker-controlled file path reaching an unsanitized file-write on the server (Jenkins master). Searching the polkadot-sdk codebase, all file-write operations with path construction from user-supplied strings (`fs::write`, `File::create`, `PathBuf` joins) live exclusively in node-side tooling that is never reachable from a permissionless entry point:

- CLI key generation (`substrate/client/cli/src/commands/generate_node_key.rs`) — operator-invoked, not attacker-reachable.
- Benchmarking CLI writers (`substrate/utils/frame/benchmarking-cli/src/pallet/writer.rs`, `.../overhead/template.rs`, `.../storage/template.rs`) — local developer tooling, paths come from CLI flags, not chain data. [1](#0-0) 
- Contract fixture build tooling (`substrate/frame/revive/fixtures/src/builder.rs`) — build-time only, not runtime-reachable. [2](#0-1) 
- Cumulus PoV export helper (`cumulus/client/consensus/aura/src/lib.rs`) — path is a fixed operator-configured export directory, filename derived from block hash/number, not from externally supplied strings. [3](#0-2) 
- Zombienet test/bundle utilities — test-only harnesses excluded per scope rules.

None of these paths are wired to a signed extrinsic, an enabled contract/`pallet-revive` call, or a permitted XCM instruction. The FRAME runtime itself (the deterministic state-transition function executed via extrinsics/XCM/contracts) performs no filesystem I/O — storage mutations go through the trie-backed `sp_io::storage` interface, not the host filesystem, so there is no code path where a permissionless user-supplied string can influence a file path written by the node on behalf of untrusted input. This breaks the CVE analog at the very first requirement (a real, unprivileged, runtime-reachable entry point), so no qualifying analog exists.

### Citations

**File:** substrate/utils/frame/benchmarking-cli/src/pallet/writer.rs (L464-481)
```rust
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
```

**File:** substrate/frame/revive/fixtures/src/builder.rs (L461-491)
```rust
fn extract_and_write_bytecode(
	compiler_json: &serde_json::Value,
	out_dir: &Path,
	file_suffix: &str,
	bytecode_type: EvmByteCodeType,
) -> Result<()> {
	if let Some(contracts) = compiler_json["contracts"].as_object() {
		for (_file_key, file_contracts) in contracts {
			if let Some(contract_map) = file_contracts.as_object() {
				for (contract_name, contract_data) in contract_map {
					// Navigate through the JSON path to find the bytecode
					let mut current = contract_data;
					for path_segment in ["evm", bytecode_type.json_key(), "object"] {
						if let Some(next) = current.get(path_segment) {
							current = next;
						} else {
							// Skip if path doesn't exist (e.g., contract has no bytecode)
							continue;
						}
					}

					if let Some(bytecode_obj) = current.as_str() {
						let bytecode_hex = bytecode_obj.strip_prefix("0x").unwrap_or(bytecode_obj);
						let binary_content = hex::decode(bytecode_hex).map_err(|e| {
							anyhow::anyhow!("Failed to decode hex for {contract_name}: {e}")
						})?;

						let out_path = out_dir.join(format!("{}{}", contract_name, file_suffix));
						fs::write(&out_path, binary_content).with_context(|| {
							format!("Failed to write {out_path:?} for {contract_name}")
						})?;
```

**File:** cumulus/client/consensus/aura/src/lib.rs (L53-74)
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
```
