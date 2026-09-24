No vulnerability found for this question.

The Dokploy issue is a classic OS command injection where user-controlled strings (`databaseName`, `backupFile`) are interpolated into shell command strings executed via `execAsync`/`execAsyncRemote`. Looking for an analogous pattern in this repo — user-controlled runtime input flowing into a constructed shell command or `Command::new()` invocation reachable from a signed extrinsic, contract call, or XCM message — turns up nothing similar.

All `Command::new`/`spawn`/`execAsync`-style usages found are confined to:
- Build tooling (`substrate/utils/wasm-builder/src/lib.rs`, `substrate/utils/wasm-builder/src/prerequisites.rs`) invoking `cargo`/`rustup` with fixed, non-runtime arguments [1](#0-0) .
- PVF worker process spawning in `polkadot/node/core/pvf`, which spawns fixed worker binaries (`execute-worker`/`prepare-worker`) with a small set of internally-controlled CLI flags, not user-supplied strings from extrinsics [2](#0-1) [3](#0-2) .
- Test/dev utilities (`substrate/test-utils/cli/src/lib.rs`, `docs/sdk/src/guides/your_first_node.rs`, `substrate/frame/staking-async/runtimes/papi-tests/src/cmd.ts`) that spawn local dev nodes/binaries with fixed args, not reachable from any chain-level user entry point [4](#0-3) .
- Shell scripts (`docker/scripts/entrypoint.sh`, `substrate/docker/run.sh`, bridge testing scripts) that only take operator-provided CLI args at container/process startup, not chain-state-derived data.

None of these constitute a real user entry point (signed extrinsic, permitted contract call, XCM execute/send, or public proof submission) whose payload is interpolated into an OS-level shell command executed by node/runtime code — which is the essential precondition for the Dokploy-class vulnerability. Polkadot SDK's runtime/pallet logic is pure Wasm-executed state-transition code; it has no code path where extrinsic-supplied strings are passed to a shell or `Command` execution. The PVF worker spawning takes only PoV/candidate binary blobs which are executed inside a sandboxed Wasmtime environment (not passed as shell arguments), so there is no analogous injection surface reachable by an unprivileged extrinsic sender.

### Citations

**File:** substrate/utils/wasm-builder/src/prerequisites.rs (L150-177)
```rust
	fn prepare_command(&self, subcommand: &str) -> Command {
		let mut cmd = self.cargo_command.command();
		// Chdir to temp to avoid including project's .cargo/config.toml
		// by accident - it can happen in some CI environments.
		cmd.current_dir(&self.temp);
		cmd.arg(subcommand);
		if !self.ignore_target {
			cmd.arg(format!("--target={}", self.target.rustc_target(self.cargo_command)));
		}
		cmd.args(&["--manifest-path", &self.manifest_path.display().to_string()]);

		if super::color_output_enabled() {
			cmd.arg("--color=always");
		}

		// manually set the `CARGO_TARGET_DIR` to prevent a cargo deadlock
		let target_dir = self.temp.path().join("target").display().to_string();
		cmd.env("CARGO_TARGET_DIR", &target_dir);

		// Make sure the host's flags aren't used here, e.g. if an alternative linker is specified
		// in the RUSTFLAGS then the check we do here will break unless we clear these.
		cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
		cmd.env_remove("RUSTFLAGS");
		// Make sure if we're called from within a `build.rs` the host toolchain won't override a
		// rustup toolchain we've picked.
		cmd.env_remove("RUSTC");
		cmd
	}
```

**File:** polkadot/node/core/pvf/src/execute/worker_interface.rs (L42-63)
```rust
pub async fn spawn(
	program_path: &Path,
	cache_path: &Path,
	executor_params: ExecutorParams,
	spawn_timeout: Duration,
	node_version: Option<&str>,
	security_status: SecurityStatus,
) -> Result<(IdleWorker, WorkerHandle), SpawnErr> {
	let mut extra_args = vec!["execute-worker"];
	if let Some(node_version) = node_version {
		extra_args.extend_from_slice(&["--node-impl-version", node_version]);
	}

	let (mut idle_worker, worker_handle) = spawn_with_program_path(
		"execute",
		program_path,
		cache_path,
		&extra_args,
		spawn_timeout,
		security_status,
	)
	.await?;
```

**File:** polkadot/node/core/pvf/src/worker_interface.rs (L61-88)
```rust
pub async fn spawn_with_program_path(
	debug_id: &'static str,
	program_path: impl Into<PathBuf>,
	cache_path: &Path,
	extra_args: &[&str],
	spawn_timeout: Duration,
	security_status: SecurityStatus,
) -> Result<(IdleWorker, WorkerHandle), SpawnErr> {
	let program_path = program_path.into();
	let worker_dir = WorkerDir::new(debug_id, cache_path).await?;
	let extra_args: Vec<String> = extra_args.iter().map(|arg| arg.to_string()).collect();
	// Hack the borrow-checker.
	let program_path_clone = program_path.clone();
	let worker_dir_clone = worker_dir.path().to_owned();
	let extra_args_clone = extra_args.clone();

	with_transient_socket_path(debug_id, |socket_path| {
		let socket_path = socket_path.to_owned();

		async move {
			let listener = match UnixListener::bind(&socket_path) {
				Ok(ok) => ok,
				Err(err) => return Err(SpawnErr::Bind { socket_path, err: err.to_string() }),
			};

			let handle =
				WorkerHandle::spawn(&program_path, &extra_args, &socket_path, &worker_dir.path())
					.map_err(|err| SpawnErr::ProcessSpawn { program_path, err: err.to_string() })?;
```

**File:** substrate/test-utils/cli/src/lib.rs (L94-100)
```rust
pub fn start_node() -> Child {
	Command::new(cargo_bin("substrate-node"))
		.stdout(process::Stdio::piped())
		.stderr(process::Stdio::piped())
		.args(&["--dev", "--tmp", "--rpc-port=45789", "--no-hardware-benchmarks"])
		.spawn()
		.unwrap()
```
