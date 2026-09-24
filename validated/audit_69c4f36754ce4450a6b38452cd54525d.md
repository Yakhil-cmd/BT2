No vulnerability found for this question.

The OpenClaw CVE describes a DoS caused by an attacker-supplied remote media URL triggering slow-read behavior against a gateway's worker pool—a scenario specific to a media-processing gateway service, not a blockchain runtime. Searching the polkadot-sdk codebase for comparable "attacker supplies a URL that a privileged/public component fetches" patterns surfaces only:

- The offchain worker HTTP client (`substrate/client/offchain/src/api/http.rs`) and its `Externalities::http_request_start`/`http_response_read_body` API [1](#0-0) , which is invoked only by runtime-defined offchain worker logic that node operators choose to run — not by any signed extrinsic, contract call, or XCM message controllable by an unprivileged remote attacker.
- `frame-remote-externalities`'s bundle/RPC downloading logic [2](#0-1)  and parallel RPC fetch workers [3](#0-2) , which are developer/testing tooling used to snapshot chain state, not production runtime code reachable by any extrinsic.
- The JSON-RPC server's own listener/rate-limiting path [4](#0-3) , which already applies per-IP rate limiting and is not a "remote media URL fetch" primitive at all.

None of these constitute a real, unprivileged user entry point (signed extrinsic, permitted XCM execute/send, or contract call) that causes the runtime, a validator, or a gateway to fetch and slow-read an attacker-supplied remote URL. There is no FRAME pallet, XCM transactor, or Cumulus/Snowbridge component in this codebase that performs outbound HTTP/media fetches driven by extrinsic-supplied URLs — the offchain HTTP API is strictly a node-operator-configured, non-consensus-critical convenience, and the CVE's bug class (generic resource exhaustion via slow reads on attacker-supplied URLs) is explicitly outside the scope of accepted findings for this exercise. No demonstrable analog exists.

### Citations

**File:** substrate/client/offchain/src/api/http.rs (L662-708)
```rust
impl Future for HttpWorker {
	type Output = ();

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
		// Reminder: this is continuously run in the background.

		// We use a `me` variable because the compiler isn't smart enough to allow borrowing
		// multiple fields at once through a `Deref`.
		let me = &mut *self;

		// We remove each element from `requests` one by one and add them back only if necessary.
		for n in (0..me.requests.len()).rev() {
			let (id, request) = me.requests.swap_remove(n);
			match request {
				HttpWorkerRequest::Dispatched(mut future) => {
					// Check for an HTTP response from the Internet.
					let response = match Future::poll(Pin::new(&mut future), cx) {
						Poll::Pending => {
							me.requests.push((id, HttpWorkerRequest::Dispatched(future)));
							continue;
						},
						Poll::Ready(Ok(response)) => response,
						Poll::Ready(Err(error)) => {
							let _ = me.to_api.unbounded_send(WorkerToApi::Fail { id, error });
							continue; // don't insert the request back
						},
					};

					// We received a response! Decompose it into its parts.
					let (head, body) = response.into_parts();
					let (status_code, headers) = (head.status, head.headers);

					let (body_tx, body_rx) = mpsc::channel(3);
					let _ = me.to_api.unbounded_send(WorkerToApi::Response {
						id,
						status_code,
						headers,
						body: body_rx,
					});

					me.requests.push((
						id,
						HttpWorkerRequest::ReadBody { body: Body::new(body), tx: body_tx },
					));
					cx.waker().wake_by_ref(); // reschedule in order to poll the new future
					continue;
				},
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

**File:** substrate/utils/frame/remote-externalities/src/lib.rs (L292-333)
```rust
		run_workers(initial_work, conn_manager, parallel, move |worker_index, range, client| {
			let all_keys = all_keys.clone();
			let last_logged_milestone = last_logged_milestone.clone();

			async move {
				trace!(
					target: LOG_TARGET,
					"Worker {worker_index}: fetching keys starting at {:?} (page_size: {})",
					HexDisplay::from(&range.start_key.0),
					range.page_size
				);

				let rpc_result = with_timeout(
					client.storage_keys_paged(
						Some(range.prefix.clone()),
						range.page_size,
						Some(range.start_key.clone()),
						Some(block),
					),
					RPC_TIMEOUT,
				)
				.await;

				let page = match rpc_result {
					Ok(Ok(p)) => p,
					Ok(Err(e)) => {
						debug!(target: LOG_TARGET, "Worker {worker_index}: RPC error: {e:?}");
						return ProcessResult::Retry {
							work: range.with_halved_page_size(),
							sleep_duration: Duration::from_secs(15),
							action: retry_action(&format!("{e:?}")),
						};
					},
					Err(()) => {
						debug!(target: LOG_TARGET, "Worker {worker_index}: timeout");
						return ProcessResult::Retry {
							work: range.with_halved_page_size(),
							sleep_duration: Duration::from_secs(5),
							action: RetryAction::Recreate,
						};
					},
				};
```

**File:** substrate/client/rpc-servers/src/lib.rs (L327-371)
```rust
		let deny_unsafe = deny_unsafe(&local_addr, &rpc_methods);

		rpc_handle.spawn(async move {
			loop {
				let (sock, remote_addr) = tokio::select! {
					res = listener.accept() => {
						match res {
							Ok(s) => s,
							Err(e) => {
								log::debug!(target: "rpc", "Failed to accept connection: {:?}", e);
								continue;
							}
						}
					}
					_ = cfg.stop_handle.clone().shutdown() => break,
				};

				let ip = remote_addr.ip();
				let cfg2 = cfg.clone();
				let service_builder2 = service_builder.clone();
				let rate_limit_whitelisted_ips2 = rate_limit_whitelisted_ips.clone();

				let svc =
					tower::service_fn(move |mut req: http::Request<hyper::body::Incoming>| {
						req.extensions_mut().insert(deny_unsafe);

						let PerConnection { methods, metrics, tokio_handle, stop_handle } =
							cfg2.clone();
						let service_builder = service_builder2.clone();

						let proxy_ip =
							if rate_limit_trust_proxy_headers { get_proxy_ip(&req) } else { None };

						let rate_limit_cfg = if rate_limit_whitelisted_ips2
							.iter()
							.any(|ips| ips.contains(proxy_ip.unwrap_or(ip)))
						{
							log::debug!(target: "rpc", "ip={ip}, proxy_ip={:?} is trusted, disabling rate-limit", proxy_ip);
							None
						} else {
							if !rate_limit_whitelisted_ips2.is_empty() {
								log::debug!(target: "rpc", "ip={ip}, proxy_ip={:?} is not trusted, rate-limit enabled", proxy_ip);
							}
							rate_limit
						};
```
