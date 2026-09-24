No vulnerability found for this question.

**Rationale:** The reported bug class is a classic server-side URL-fetch SSRF: an authenticated but unprivileged user supplies a URL string that a server-side component (`pyload`) hands directly to `pycurl` (`get_url(url)`), with no scheme allowlist or destination validation, allowing `file://`, `gopher://`, and internal-network access from a request-handling process.

For this to have a genuine analog in `polkadot-sdk`, there would need to be a **deterministic, consensus-critical code path** (an extrinsic handler / pallet `dispatch`, contracts/revive host call, or XCM executor step) that takes attacker-controlled input from a signed extrinsic and uses it to make an outbound network request as part of block execution. I searched for any URL-fetching logic reachable from user-controlled input.

The only network-fetch capability in the runtime stack is the **offchain worker HTTP API** (`sp_io::offchain::http_request_start`, wired through `substrate/client/offchain/src/api/http.rs` and exposed to runtimes via `sp_runtime::offchain::http::Request`) [1](#0-0) [2](#0-1) . This capability is structurally disqualifying as an SSRF analog because:

- It only runs in the **offchain worker context**, which is explicitly non-deterministic and cannot alter state — any storage writes during its execution are discarded, and the only way to affect the chain is by submitting a new signed extrinsic through normal validation [3](#0-2) .
- Whether/when it runs is a **node-operator decision** (`sc_cli::RunCmd::offchain_worker_params`), not something an ordinary unprivileged extrinsic sender can trigger deterministically on arbitrary nodes [4](#0-3) .
- Any URL used by an offchain worker is chosen by the **pallet/runtime author's own code**, not derived from unsanitized user extrinsic input in the way `parse_urls(url)` directly forwards attacker input to `get_url()`.

Other URL-consuming code found (`cumulus/client/relay-chain-rpc-interface`'s WS connection to `--relay-chain-rpc-urls`, and the zombienet test fixture's `download()` helper) are either **node-operator CLI configuration** [5](#0-4)  or **test-only tooling** [6](#0-5) , both explicitly excluded by the review method (privileged prerequisites / tests-and-tooling exclusion).

No FRAME pallet, `pallet-contracts`/`pallet-revive` host function, or `pallet-xcm` executor step performs an outbound network fetch keyed on unsanitized user/extrinsic input during deterministic dispatch — this is by design, since blockchain state transitions must be deterministic and cannot depend on live network I/O. Without such an entry point, there is no demonstrable Polkadot SDK analog to the SSRF described in the pyLoad advisory.

### Citations

**File:** substrate/primitives/runtime/src/offchain/http.rs (L205-227)
```rust
	pub fn send(self) -> Result<PendingRequest, HttpError> {
		let meta = &[];

		// start an http request.
		let id = sp_io::offchain::http_request_start(self.method.as_ref(), self.url, meta)
			.map_err(|_| HttpError::IoError)?;

		// add custom headers
		for header in &self.headers {
			sp_io::offchain::http_request_add_header(id, header.name(), header.value())
				.map_err(|_| HttpError::IoError)?
		}

		// write body
		for chunk in self.body {
			sp_io::offchain::http_request_write_body(id, chunk.as_ref(), self.deadline)?;
		}

		// finalize the request
		sp_io::offchain::http_request_write_body(id, &[], self.deadline)?;

		Ok(PendingRequest { id })
	}
```

**File:** substrate/client/offchain/src/api/http.rs (L146-183)
```rust
impl HttpApi {
	/// Mimics the corresponding method in the offchain API.
	pub fn request_start(&mut self, method: &str, uri: &str) -> Result<HttpRequestId, ()> {
		// Start by building the prototype of the request.
		// We do this first so that we don't touch anything in `self` if building the prototype
		// fails.
		let (body_sender, receiver) = mpsc::channel(0);
		let body = StreamBody::new(receiver);
		let body = BoxBody::new(body);
		let mut request = hyper::Request::new(body);
		*request.method_mut() = hyper::Method::from_bytes(method.as_bytes()).map_err(|_| ())?;
		*request.uri_mut() = hyper::Uri::from_maybe_shared(uri.to_owned()).map_err(|_| ())?;

		let new_id = self.next_id;
		debug_assert!(!self.requests.contains_key(&new_id));
		match self.next_id.0.checked_add(1) {
			Some(new_id) => self.next_id.0 = new_id,
			None => {
				tracing::error!(
					target: LOG_TARGET,
					"Overflow in offchain worker HTTP request ID assignment"
				);
				return Err(());
			},
		};
		self.requests
			.insert(new_id, HttpApiRequest::NotDispatched(request, body_sender));

		tracing::trace!(
			target: LOG_TARGET,
			id = %new_id.0,
			%method,
			%uri,
			"Requested started",
		);

		Ok(new_id)
	}
```

**File:** docs/sdk/src/reference_docs/frame_offchain_workers.rs (L17-34)
```rust
//! Offchain workers are in principle not different in any way: It is a runtime API exposed by the
//! wasm blob ([`sp_offchain::OffchainWorkerApi`]), and the node software calls into it when it
//! deems fit. But, crucially, this API call is different in that:
//!
//! 1. It can have no impact on the state ie. it is _OFF (the) CHAIN_. If any state is altered
//!    during the execution of this API call, it is discarded.
//! 2. It has access to an extended set of host functions that allow the wasm blob to do more. For
//!    example, call into HTTP requests.
//!
//! > The main way through which an offchain worker can interact with the state is by submitting an
//! > extrinsic to the chain. This is the ONLY way to alter the state from an offchain worker.
//! > [`pallet_example_offchain_worker`] provides an example of this.
//!
//!
//! Given the "Off Chain" nature of this API, it is important to remember that calling this API is
//! entirely optional. Some nodes might call into it, some might not, and it would have no impact on
//! the execution of your blockchain because no state is altered no matter the execution of the
//! offchain worker API.
```

**File:** docs/sdk/src/reference_docs/frame_offchain_workers.rs (L36-38)
```rust
//! Substrate's CLI allows some degree of configuration about this, allowing node operators to
//! specify when they want to run the offchain worker API. See
//! [`sc_cli::RunCmd::offchain_worker_params`].
```

**File:** cumulus/client/cli/src/lib.rs (L291-305)
```rust
	/// Creates a less resource-hungry node that retrieves relay chain data from an RPC endpoint.
	///
	/// The provided URLs should point to RPC endpoints of the relay chain.
	/// This node connects to the remote nodes following the order they were specified in. If the
	/// connection fails, it attempts to connect to the next endpoint in the list.
	///
	/// Note: This option doesn't stop the node from connecting to the relay chain network but
	/// reduces bandwidth use.
	#[arg(
		long,
		value_parser = validate_relay_chain_url,
		num_args = 0..,
		alias = "relay-chain-rpc-url"
	)]
	pub relay_chain_rpc_urls: Vec<Url>,
```

**File:** cumulus/zombienet/zombienet-sdk/tests/zombie_ci/storage_chain/fixture.rs (L119-129)
```rust
fn download(url: &str, dst: &Path) -> Result<()> {
	log::info!("Downloading bundle from {} -> {}", url, dst.display());
	let status = std::process::Command::new("curl")
		.args(["-fsSL", "-o"])
		.arg(dst)
		.arg(url)
		.status()
		.with_context(|| format!("Failed to spawn curl for {url}"))?;
	anyhow::ensure!(status.success(), "curl failed downloading {url}");
	Ok(())
}
```
