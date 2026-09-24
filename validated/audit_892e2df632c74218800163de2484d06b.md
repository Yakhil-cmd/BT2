No vulnerability found for this question.

The Centreon CVE describes OS command injection via string concatenation into a shell command in a web application's backup configuration feature — a privileged admin-only PHP web feature. Searching the Polkadot SDK codebase for analogous shell/process invocation patterns only surfaces node-level tooling: PVF worker process spawning [1](#0-0) , security sandbox checks [2](#0-1) , benchmark/CLI test harnesses that shell out to `cargo_bin` [3](#0-2) , and build/test scripts [4](#0-3) .

None of these constitute a real user entry point as required by the analysis method — they are not signed extrinsics, contract calls, or XCM messages reachable by an unprivileged attacker. They are node-operator CLI tooling, local test harnesses, and CI/build scripts, all requiring local/operator access rather than on-chain privilege. There is no "backup configuration" feature or analogous string-concatenation-into-shell-command pattern reachable through FRAME pallets, XCM, or contracts/revive that any signed account (even a privileged one like sudo/governance-controlled origin) could trigger through normal runtime dispatch. This bug class (OS command injection in a web admin backup feature) has no demonstrable analog in the Polkadot SDK's runtime/consensus code paths.

### Citations

**File:** polkadot/node/core/pvf/src/worker_interface.rs (L231-251)
```rust
	fn spawn(
		program: impl AsRef<Path>,
		extra_args: &[String],
		socket_path: impl AsRef<Path>,
		worker_dir_path: impl AsRef<Path>,
	) -> io::Result<Self> {
		// Clear all env vars from the spawned process.
		let mut command = process::Command::new(program.as_ref());
		command.env_clear();

		command.env("RUST_LOG", sc_tracing::logging::get_directives().join(","));

		let mut child = command
			.args(extra_args)
			.arg("--socket-path")
			.arg(socket_path.as_ref().as_os_str())
			.arg("--worker-dir-path")
			.arg(worker_dir_path.as_ref().as_os_str())
			.stdout(std::process::Stdio::piped())
			.kill_on_drop(true)
			.spawn()?;
```

**File:** polkadot/node/core/pvf/src/security.rs (L276-294)
```rust
async fn spawn_process_for_security_check<I, S>(
	prepare_worker_program_path: &Path,
	check_arg: &'static str,
	extra_args: I,
) -> Result<(), String>
where
	I: IntoIterator<Item = S>,
	S: AsRef<std::ffi::OsStr>,
{
	let mut command = tokio::process::Command::new(prepare_worker_program_path);
	// Clear env vars. (In theory, running checks with different env vars could result in different
	// outcomes of the checks.)
	command.env_clear();
	// Add back any env vars we want to keep.
	if let Ok(value) = std::env::var("RUST_LOG") {
		command.env("RUST_LOG", value);
	}

	match command.arg(check_arg).args(extra_args).output().await {
```

**File:** substrate/bin/node/cli/tests/build_spec_works.rs (L27-32)
```rust
	let output = Command::new(cargo_bin("substrate-node"))
		.args(&["build-spec", "--dev", "-d"])
		.arg(base_path.path())
		.output()
		.unwrap();
	assert!(output.status.success());
```

**File:** cumulus/scripts/create_shell_spec.sh (L1-16)
```shellscript
#!/usr/bin/env bash

usage() {
    echo Usage:
    echo "$0 <srtool compressed runtime>"
    exit 1
}

set -e

rt_path=$1

binary="./target/release/polkadot-parachain"

# build the chain spec we'll manipulate
$binary build-spec --chain shell > shell-spec-plain.json
```
