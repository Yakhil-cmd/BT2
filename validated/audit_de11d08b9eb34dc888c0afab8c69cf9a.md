No vulnerability found for this question.

All file-path-related code identified (chain-spec-builder, benchmarking-cli's Handlebars template writer, sysinfo, keystore/import commands) is local, operator-only CLI tooling that reads paths supplied via command-line arguments by the node operator — not attacker-controlled input reachable through a signed extrinsic, enabled contract call, or XCM message [1](#0-0) [2](#0-1) [3](#0-2) .

The Solon advisory concerns a web-server template-rendering endpoint (`/aa`, `render_mav`) that takes an HTTP request parameter and uses it to build a filesystem path without sanitization, enabling arbitrary file read via `../` sequences from a remote, unauthenticated network caller. Polkadot SDK runtimes execute inside a deterministic Wasm sandbox with no filesystem access, and none of the "real user entry" surfaces named in the method (signed extrinsics, contract/`pallet-revive` calls, XCM execute/send, bridge proof submission) accept a value that is ever used to open, read, or render a file on disk — that class of operation only exists in offline, operator-invoked CLI utilities (chain-spec-builder, benchmarking-cli, node-key inspection, sysinfo), which are explicitly out of scope as they require a privileged/local operator, not a remote attacker. There is no reachable analog of path traversal via attacker-supplied input in the runtime/extrinsic/XCM/bridge boundaries that this report's bug class would require.

### Citations

**File:** substrate/utils/frame/benchmarking-cli/src/pallet/writer.rs (L396-408)
```rust
	let template: String = match &cmd.template {
		Some(template_file) => fs::read_to_string(template_file)?,
		None => TEMPLATE.to_string(),
	};

	// Use header if provided
	let header_text = match &cmd.header {
		Some(header_file) => {
			let text = fs::read_to_string(header_file)?;
			text
		},
		None => String::new(),
	};
```

**File:** substrate/bin/utils/chain-spec-builder/src/lib.rs (L349-362)
```rust
		GenesisBuildAction::Patch(PatchCmd { ref patch_path }) => {
			let patch = fs::read(patch_path.as_path())
				.map_err(|e| format!("patch file {patch_path:?} shall be readable: {e}"))?;
			builder.with_genesis_config_patch(serde_json::from_slice::<Value>(&patch[..]).map_err(
				|e| format!("patch file {patch_path:?} shall contain a valid json: {e}"),
			)?)
		},
		GenesisBuildAction::Full(FullCmd { ref config_path }) => {
			let config = fs::read(config_path.as_path())
				.map_err(|e| format!("config file {config_path:?} shall be readable: {e}"))?;
			builder.with_genesis_config(serde_json::from_slice::<Value>(&config[..]).map_err(
				|e| format!("config file {config_path:?} shall contain a valid json: {e}"),
			)?)
		},
```

**File:** substrate/client/cli/src/commands/inspect_node_key.rs (L53-63)
```rust
impl InspectNodeKeyCmd {
	/// runs the command
	pub fn run(&self) -> Result<(), Error> {
		let mut file_data = match &self.file {
			Some(file) => fs::read(&file)?,
			None => {
				let mut buf = Vec::with_capacity(64);
				io::stdin().lock().read_to_end(&mut buf)?;
				buf
			},
		};
```
