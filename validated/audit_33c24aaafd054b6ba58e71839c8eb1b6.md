No vulnerability found for this question.

I investigated potential analogs to the CPython `http.client` unbounded-read-buffering DoS (server controls `Content-Length`, client blindly buffers full response into memory) across the Polkadot SDK:

1. **Offchain worker HTTP client** (`substrate/client/offchain/src/api/http.rs`, `substrate/primitives/runtime/src/offchain/http.rs`) — this is the closest structural analog, since it wraps a `hyper` client used to fetch external HTTP responses inside offchain workers. However, this code path is not reachable by an unprivileged attacker through a signed extrinsic, XCM message, or contract call — it is a node-local, node-operator-initiated network client, and the offchain worker code chooses which URLs to fetch. There's no "real user entry" here in the required sense; the requester (offchain worker logic compiled into the runtime and run locally) is not an attacker-controlled remote party dictating body size to a victim without consent. Also, reads are chunked into a bounded `[u8; 4096]` buffer per iterator step (`substrate/primitives/runtime/src/offchain/http.rs:350`) rather than reading-to-end unboundedly. [1](#0-0) [2](#0-1) 

2. **libp2p request-response protocol codec** (`substrate/client/network/src/request_responses.rs`) — this explicitly enforces `max_request_size`/`max_response_size` checks before allocating buffers, precluding the "no read amount specified" class of bug. [3](#0-2) 

3. **PVF execute-worker pipe read** (`polkadot/node/core/pvf/execute-worker/src/lib.rs`) uses `read_to_end` on an internal pipe from a locally spawned child process, not an externally-reachable, attacker-controlled input. [4](#0-3) 

None of these constitute a demonstrable analog reachable by an unprivileged attacker through a signed extrinsic, contract call, or XCM message affecting consensus state, issuance, or dispatch — the prompt's required threat model. The closest match (offchain HTTP client) is node-operator-controlled infrastructure code, not part of the on-chain state transition function, and falls under the excluded categories of generic resource-exhaustion / oversized-input claims without a real user entry point.

### Citations

**File:** substrate/primitives/runtime/src/offchain/http.rs (L347-354)
```rust
pub struct ResponseBody {
	id: RequestId,
	error: Option<HttpError>,
	buffer: [u8; 4096],
	filled_up_to: Option<usize>,
	position: usize,
	deadline: Option<Timestamp>,
}
```

**File:** substrate/client/offchain/src/api/http.rs (L710-737)
```rust
				HttpWorkerRequest::ReadBody { mut body, mut tx } => {
					// Before reading from the HTTP response, check that `tx` is ready to accept
					// a new chunk.
					match tx.poll_ready(cx) {
						Poll::Ready(Ok(())) => {},
						Poll::Ready(Err(_)) => continue, // don't insert the request back
						Poll::Pending => {
							me.requests.push((id, HttpWorkerRequest::ReadBody { body, tx }));
							continue;
						},
					}

					match Pin::new(&mut body).poll_frame(cx) {
						Poll::Ready(Some(Ok(chunk))) => {
							let _ = tx.start_send(Ok(chunk));
							me.requests.push((id, HttpWorkerRequest::ReadBody { body, tx }));
							cx.waker().wake_by_ref(); // reschedule in order to continue reading
						},
						Poll::Ready(Some(Err(err))) => {
							let _ = tx.start_send(Err(err));
							// don't insert the request back
						},
						Poll::Ready(None) => {}, // EOF; don't insert the request back
						Poll::Pending => {
							me.requests.push((id, HttpWorkerRequest::ReadBody { body, tx }));
						},
					}
				},
```

**File:** substrate/client/network/src/request_responses.rs (L1092-1112)
```rust
		let length = match unsigned_varint::aio::read_usize(&mut io).await {
			Ok(l) => l,
			Err(unsigned_varint::io::ReadError::Io(err))
				if matches!(err.kind(), io::ErrorKind::UnexpectedEof) =>
			{
				return Ok(Err(()))
			},
			Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidInput, err)),
		};

		if length > usize::try_from(self.max_response_size).unwrap_or(usize::MAX) {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Response size exceeds limit: {} > {}", length, self.max_response_size),
			));
		}

		// Read the payload.
		let mut buffer = vec![0; length];
		io.read_exact(&mut buffer).await?;
		Ok(Ok(buffer))
```

**File:** polkadot/node/core/pvf/execute-worker/src/lib.rs (L616-622)
```rust
	// Read from the child. Don't decode unless the process exited normally, which we check later.
	let mut received_data = Vec::new();
	pipe_read
		.read_to_end(&mut received_data)
		// Could not decode job response. There is either a bug or the job was hijacked.
		// Should retry at any rate.
		.map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
```
