### Title
`system_reservedPeers` RPC method leaks configured reserved-peer addresses to unprivileged RPC callers, bypassing the `DenyUnsafe` gate applied to its sibling mutator methods - ([File: substrate/client/rpc/src/system/mod.rs])

### Summary
The Jenkins CVE-2023-32988 root cause is a missing permission check on a *read/enumeration* endpoint whose paired *write* endpoints are properly gated, letting a low-privileged caller (`Overall/Read`) enumerate credential identifiers that should require a higher permission. The Substrate JSON-RPC `system` module exhibits the same asymmetric-gating pattern: `system_add_reserved_peer` and `system_remove_reserved_peer` both call `check_if_safe(ext)` (the Substrate equivalent of a permission gate that denies "unsafe" calls to external/untrusted RPC callers), but their read counterpart `system_reserved_peers`, which returns the full list of the node's configured reserved-peer multiaddresses, does not.

### Finding Description
In `substrate/client/rpc/src/system/mod.rs`, `system_add_reserved_peer` and `system_remove_reserved_peer` explicitly invoke `check_if_safe(ext)?` before mutating the reserved-peer set: [1](#0-0) 

`system_peers` and `system_network_state`, which expose comparable network-topology data, are likewise gated: [2](#0-1) 

However `system_reserved_peers` — the read-side companion of the two gated mutators — takes no `Extensions` parameter and performs no `check_if_safe` call at all: [3](#0-2) 

`check_if_safe` is backed by the `DenyUnsafe` policy, which is the boundary that decides whether a given RPC surface is reachable by an untrusted/external caller versus only a trusted local operator: [4](#0-3) 

Because `system_reserved_peers` skips this check, any RPC client that can reach the node's JSON-RPC endpoint under the `DenyUnsafe::Yes` policy (the mode used for externally-exposed/public endpoints) can still call `system_reservedPeers` and obtain the operator-configured reserved-peer list, even though the semantically related write operations (`system_addReservedPeer` / `system_removeReservedPeer`) are correctly denied in that same mode. This is the direct Substrate/FRAME analog of the Jenkins bug: a missing permission check on an enumeration method whose sibling mutating methods are properly protected.

### Impact Explanation
Reserved peers are typically security-sensitive network topology configured by the node operator (e.g., dedicated links to validator/collator or sentry-node infrastructure) specifically to keep such peers off the public DHT/discovery path. Disclosing this list to any externally-reachable, unprivileged RPC caller undermines that intent and can facilitate targeted network-level reconnaissance (e.g., identifying and directly probing/DoS-ing a validator's sentry or reserved peers) — a lower-impact information-disclosure issue, consistent with the Medium severity of the Jenkins analog (information disclosure via missing permission check, no direct fund loss or consensus break).

### Likelihood Explanation
Any deployment that exposes the JSON-RPC interface externally with the default `DenyUnsafe::Yes` policy (the standard/recommended configuration for public-facing nodes) is affected; no special role, governance action, or privileged key is required — a plain unauthenticated RPC client can call the method. Likelihood is High for reachability, but actual damage is limited to information disclosure of network topology, not funds/state integrity.

### Recommendation
Add `check_if_safe(ext)?` to `system_reserved_peers` (mirroring `system_add_reserved_peer`/`system_remove_reserved_peer`) so the read path enforces the same `DenyUnsafe` boundary as its write counterparts. Consider auditing other read/enumeration RPC methods in this module (`system_node_roles`, `system_sync_state`) for the same missing-check asymmetry against their related gated methods.

### Proof of Concept
No live network test was executed (per scope rules, no traffic was sent to any deployed node). The finding is based on static code inspection showing the asymmetric application of `check_if_safe` across sibling methods in the same trait impl:
- Gated: `system_add_reserved_peer`, `system_remove_reserved_peer`, `system_peers`, `system_network_state`, `system_add_log_filter`, `system_reset_log_filter`.
- Not gated: `system_reserved_peers` (also `system_node_roles`, `system_sync_state`, though these carry less sensitive data).

A minimal reproduction would be: start a node with `--rpc-external` (or any config that sets `DenyUnsafe::Yes` for the listening interface) with at least one `--reserved-nodes` entry configured, then issue an unauthenticated JSON-RPC call `system_reservedPeers` from a normal external client and observe it succeeds and returns the reserved multiaddress list, while `system_addReservedPeer`/`system_removeReservedPeer` calls from the same client are rejected with the "RPC call is unsafe to be called externally" error. This reproduction was not executed against a live/deployed node in this review; it is derived directly from the source code shown above and is a straightforward, deterministic call-path argument rather than an untested speculation.

**Confidence caveat:** I could not verify from the index alone whether this asymmetry is a long-standing, deliberately-accepted design choice in upstream Substrate (i.e., whether Parity considers the reserved-peers list non-sensitive by design) or an oversight. I was not able to retrieve the original PR/commit history explaining the intended safety classification of `system_reservedPeers` (`get_recent_commits` only showed "Initial commit" for this snapshot). This should be validated by a Devin session with full repository history/blame access before treating it as a confirmed, previously-unreported issue.

### Citations

**File:** substrate/client/rpc/src/system/mod.rs (L118-133)
```rust
	async fn system_peers(
		&self,
		ext: &Extensions,
	) -> Result<Vec<PeerInfo<B::Hash, <B::Header as HeaderT>::Number>>, Error> {
		check_if_safe(ext)?;
		let (tx, rx) = oneshot::channel();
		let _ = self.send_back.unbounded_send(Request::Peers(tx));
		rx.await.map_err(|e| Error::Internal(e.to_string()))
	}

	async fn system_network_state(&self, ext: &Extensions) -> Result<JsonValue, Error> {
		check_if_safe(ext)?;
		let (tx, rx) = oneshot::channel();
		let _ = self.send_back.unbounded_send(Request::NetworkState(tx));
		rx.await.map_err(|e| Error::Internal(e.to_string()))
	}
```

**File:** substrate/client/rpc/src/system/mod.rs (L135-159)
```rust
	async fn system_add_reserved_peer(&self, ext: &Extensions, peer: String) -> Result<(), Error> {
		check_if_safe(ext)?;
		let (tx, rx) = oneshot::channel();
		let _ = self.send_back.unbounded_send(Request::NetworkAddReservedPeer(peer, tx));
		match rx.await {
			Ok(Ok(())) => Ok(()),
			Ok(Err(e)) => Err(e),
			Err(e) => Err(Error::Internal(e.to_string())),
		}
	}

	async fn system_remove_reserved_peer(
		&self,
		ext: &Extensions,
		peer: String,
	) -> Result<(), Error> {
		check_if_safe(ext)?;
		let (tx, rx) = oneshot::channel();
		let _ = self.send_back.unbounded_send(Request::NetworkRemoveReservedPeer(peer, tx));
		match rx.await {
			Ok(Ok(())) => Ok(()),
			Ok(Err(e)) => Err(e),
			Err(e) => Err(Error::Internal(e.to_string())),
		}
	}
```

**File:** substrate/client/rpc/src/system/mod.rs (L161-165)
```rust
	async fn system_reserved_peers(&self) -> Result<Vec<String>, Error> {
		let (tx, rx) = oneshot::channel();
		let _ = self.send_back.unbounded_send(Request::NetworkReservedPeers(tx));
		rx.await.map_err(|e| Error::Internal(e.to_string()))
	}
```

**File:** substrate/client/rpc-api/src/policy.rs (L26-53)
```rust
/// Checks if the RPC call is safe to be called externally.
pub fn check_if_safe(ext: &jsonrpsee::Extensions) -> Result<(), UnsafeRpcError> {
	match ext.get::<DenyUnsafe>().map(|deny_unsafe| deny_unsafe.check_if_safe()) {
		Some(Ok(())) => Ok(()),
		Some(Err(e)) => Err(e),
		None => unreachable!("DenyUnsafe extension is always set by the substrate rpc server; qed"),
	}
}

/// Signifies whether a potentially unsafe RPC should be denied.
#[derive(Clone, Copy, Debug)]
pub enum DenyUnsafe {
	/// Denies only potentially unsafe RPCs.
	Yes,
	/// Allows calling every RPCs.
	No,
}

impl DenyUnsafe {
	/// Returns `Ok(())` if the RPCs considered unsafe are safe to call,
	/// otherwise returns `Err(UnsafeRpcError)`.
	pub fn check_if_safe(self) -> Result<(), UnsafeRpcError> {
		match self {
			DenyUnsafe::Yes => Err(UnsafeRpcError),
			DenyUnsafe::No => Ok(()),
		}
	}
}
```
