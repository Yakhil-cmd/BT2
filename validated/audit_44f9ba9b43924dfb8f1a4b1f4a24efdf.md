No vulnerability found for this question.

The CVE describes a Linux kernel NIC driver (`hinic`) leaking allocated CMDQ memory when `hinic_set_cmdq_depth()` fails during `hinic_init_cmdqs()` — a resource-cleanup bug on an error path in privileged, hardware-adjacent kernel driver initialization code with no analog to a blockchain runtime's attacker-reachable surface.

I searched the repository for comparable patterns (initialization-failure cleanup gaps, CMDQ/queue-depth style resource allocation, and known memory-leak fixes already tracked in `prdoc/`), but every relevant memory-leak instance found is either:
- already-fixed internal node/networking bookkeeping (e.g. `sc-network` litep2p address pruning, availability-distribution Jaeger spans, statement-distribution request cleanup) [1](#0-0) [2](#0-1) [3](#0-2) , or
- test/dependency-only code (`substrate/client/rpc-spec-v2/src/common/connections.rs` tests, `substrate/client/hop/src/pool.rs` tests) [4](#0-3) ,

none of which is reachable through a real, unprivileged user entry point (signed extrinsic, contract call, or XCM message) with attacker-controlled input and measurable on-chain loss, as required by the scan method. There is no init-time queue/resource-allocation path in FRAME pallets, PVF host/queue, or XCM/bridge code analogous to a driver's error-path resource leak that is (a) attacker-triggerable without privilege and (b) causes a demonstrable integrity break or loss rather than generic node-side resource growth. Per the stated rejection criteria, unbounded-loop/memory-growth-only scenarios and config/test-only findings are explicitly excluded, and forcing this kernel-driver bug class onto FRAME/XCM/runtime code would not be a legitimate analog.

### Citations

**File:** prdoc/stable2412/pr_5998.prdoc (L1-15)
```text
# Schema: Polkadot SDK PRDoc Schema (prdoc) v1.0.0
# See doc at https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/prdoc/schema_user.json

title: Fix memory leak in litep2p public addresses

doc:
  - audience: [ Node Dev, Node Operator ]
    description: |
     This PR bounds the number of public addresses of litep2p to 32 entries.
     This ensures we do not increase the number of addresses over time, and that the DHT
     authority records will not exceed the upper size limit.

crates:
  - name: sc-network
    bump: patch
```

**File:** prdoc/1.15.1/pr_5321.prdoc (L1-11)
```text
title: fix availability-distribution Jaeger spans memory leak

doc:
  - audience: Node Dev
    description: |
      Fixes a memory leak which caused the Jaeger span storage in availability-distribution to never be pruned and therefore increasing indefinitely.
      This was caused by improper handling of finalized heads. More info in https://github.com/paritytech/polkadot-sdk/issues/5258

crates:
  - name: polkadot-availability-distribution
    bump: patch
```

**File:** prdoc/stable2606/pr_11820.prdoc (L1-23)
```text
title: Fix statement-distribution request cleanup on leaf deactivation

doc:
- audience: Node Dev
  description: |-
    `handle_deactivate_leaves` in statement-distribution v2 was cleaning up outgoing
    attested-candidate requests using the wrong key: it called
    `remove_by_scheduling_parent(*leaf)` once per pruned ancestor, instead of
    `remove_by_scheduling_parent(pruned_rp)` once per pruned relay parent. As a result,
    requests tied to ancestors pruned alongside a deactivated leaf were never cleaned up,
    leaking entries in the `RequestManager`.

    The bug was introduced in #1436 (vstaging rework, 2023) and was latent because the
    stale entries only caused gradual memory growth and wasted retry cycles, not
    correctness failures.

    Also adds unit tests covering the full cleanup contract of `handle_deactivate_leaves`
    (implicit view pruning, `per_scheduling_parent`, request manager, `per_session`,
    and the "last session's topology is retained" edge case).

crates:
- name: polkadot-statement-distribution
  bump: patch
```

**File:** substrate/client/rpc-spec-v2/src/common/connections.rs (L180-218)
```rust
/// RAII wrapper that ensures the identifier is unregistered if the object is dropped.
pub struct RegisteredConnection {
	connection_id: ConnectionId,
	identifier: String,
	rpc_connections: RpcConnections,
}

impl Drop for RegisteredConnection {
	fn drop(&mut self) {
		self.rpc_connections.unregister_identifier(self.connection_id, &self.identifier);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reserve_space() {
		let rpc_connections = RpcConnections::new(2);
		let conn_id = ConnectionId(1);
		let reserved = rpc_connections.reserve_space(conn_id);

		assert!(reserved.is_some());
		assert_eq!(1, rpc_connections.data.lock().get(&conn_id).unwrap().num_identifiers);
		assert_eq!(rpc_connections.data.lock().len(), 1);

		let reserved = reserved.unwrap();
		let registered = reserved.register("identifier1".to_string()).unwrap();
		assert!(rpc_connections.contains_identifier(conn_id, "identifier1"));
		assert_eq!(1, rpc_connections.data.lock().get(&conn_id).unwrap().num_identifiers);
		drop(registered);

		// Data is dropped.
		assert!(rpc_connections.data.lock().get(&conn_id).is_none());
		assert!(rpc_connections.data.lock().is_empty());
		// Checks can still happen.
		assert!(!rpc_connections.contains_identifier(conn_id, "identifier1"));
	}
```
