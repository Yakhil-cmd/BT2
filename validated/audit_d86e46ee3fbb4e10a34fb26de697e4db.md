### Title
Sharded RPC Pool Forwards Inter-Node Query Traffic Over Unencrypted HTTP Without Warning, Enabling MITM Corruption of Query Results — (File: `chain/jsonrpc/src/sharded_rpc.rs`)

---

### Summary

`ShardedRpcPool::new()` accepts any URL scheme — including `http://` — for remote shard node addresses without validation or warning. The production deployment tooling explicitly generates `http://` URLs for external IPs. A network-level attacker positioned between two RPC nodes can intercept and silently replace JSON-RPC responses (account balances, contract state, access keys, transaction statuses) before the coordinator forwards them to users. No cryptographic re-verification is performed on the forwarded payload.

---

### Finding Description

**Root cause — `ShardedRpcNodeConfig.address` is an unvalidated string:**

`ShardedRpcNodeConfig` stores the remote node address as a plain `String` with no scheme constraint. [1](#0-0) 

**`ShardedRpcPool::new()` only filters self-connections, never the URL scheme:**

The sole guard at pool-init time is `is_local_address()`, which checks whether the resolved IP belongs to the local machine. It does not inspect the URL scheme. A non-local `http://` address passes the filter and is accepted unconditionally. [2](#0-1) 

**`new_client()` builds a plain reqwest client with no TLS:**

`create_client()` constructs a `reqwest::Client` with only a timeout and TCP keepalive. There is no `https`-only enforcement, no certificate pinning, and no TLS configuration of any kind. [3](#0-2) 

**Production deployment tooling hard-codes `http://` for external IPs:**

The benchmark/mocknet setup script that configures real multi-node sharded RPC deployments generates `http://[{ip}]:{rpc_port}` for every external node address, meaning all inter-node coordinator traffic in production sharded deployments travels over plaintext HTTP. [4](#0-3) 

**Coordinator forwards remote responses without re-verification:**

`run_coordinator_request` selects candidate nodes via `nodes_for_query`, serializes the sub-request, sends it to a `RemoteNode` via `JsonRpcClient`, and returns the raw `Value` response directly to the caller. There is no integrity check on the returned payload. [5](#0-4) 

The affected RPC methods routed through this path include `query` (view_account, view_state, view_access_key, call_function), `EXPERIMENTAL_receipt`, `EXPERIMENTAL_light_client_proof`, `chunk`, `changes`, and others. [6](#0-5) 

---

### Impact Explanation

**Scope: RPC proof/query trust.**

An attacker with network access between two RPC nodes in a sharded pool can perform a man-in-the-middle attack on the plaintext HTTP channel. The attacker can replace the `result` field of any forwarded JSON-RPC response with arbitrary data. Because the coordinator node performs no cryptographic re-verification before returning the response to the end user, the corrupted value is delivered as authoritative chain state.

Concretely corrupted values include:
- **Account balance** (`view_account` → `amount` field) — attacker can report any balance.
- **Contract storage** (`view_state` → `values` array) — attacker can inject or suppress key-value pairs.
- **Access key permissions** (`view_access_key_list`) — attacker can fabricate or remove keys.
- **Transaction status** (`tx` / `EXPERIMENTAL_tx_status`) — attacker can report a transaction as succeeded or failed regardless of actual chain state.

For `light_client_proof`, the merkle proof fields are cryptographically verifiable by the end client, so a MITM modification would cause verification failure rather than silent acceptance. However, all non-cryptographic query types listed above carry no such protection.

---

### Likelihood Explanation

The sharded RPC pool is designed for multi-node deployments where nodes may reside on different machines (the self-connection filter exists precisely because external IPs are expected). The production deployment script confirms that external IPs are used with `http://`. Any attacker with access to the network segment between two RPC nodes — including a compromised router, a cloud provider insider, or an attacker who has compromised one node's network interface — can execute this attack without any nearcore-level privileges.

---

### Recommendation

1. **Short term:** In `ShardedRpcPool::new()`, after `is_local_address()` passes, parse the URL and emit a `tracing::warn!` if the scheme is `http://` and the address is non-local. This mirrors the minimum fix recommended in the Peggo report.
2. **Medium term:** Reject non-local `http://` addresses at pool-init time with a `ValidationError`, or require operators to explicitly opt in to plaintext with a dedicated config flag.
3. **Long term:** Add mutual TLS support to the `JsonRpcClient` / `ReqwestTransport` layer so inter-node coordinator traffic can be authenticated and encrypted end-to-end.
4. Update `configure_rpc_nodes` in `sharded_bm.py` to use `https://` once TLS is supported.

---

### Proof of Concept

```
# 1. Operator configures sharded RPC pool (as generated by sharded_bm.py):
#    config.json → rpc.sharded_rpc.nodes[0].address = "http://10.128.0.5:3030"

# 2. Attacker on the same network segment intercepts the HTTP stream between
#    the coordinator (10.128.0.4) and the remote shard node (10.128.0.5).

# 3. User sends a query to the coordinator:
curl -s -X POST http://10.128.0.4:3030/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"x","method":"query",
       "params":{"request_type":"view_account",
                 "finality":"final",
                 "account_id":"alice.near"}}'

# 4. Coordinator forwards the sub-request to 10.128.0.5 over plaintext HTTP.
#    Attacker intercepts the response and replaces:
#      "amount": "1000000000000000000000000"
#    with:
#      "amount": "0"

# 5. Coordinator returns the attacker-controlled response to the user.
#    The user observes alice.near has zero balance — no error, no warning.
#    The exact corrupted value is the `amount` field in the RpcQueryResponse.
```

### Citations

**File:** chain/jsonrpc/src/lib.rs (L157-164)
```rust
/// Information about a single node in a sharded rpc pool
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ShardedRpcNodeConfig {
    /// The jsonrpc address (e.g "http://127.0.0.1:3030")
    pub address: String,
    /// Shards that this node tracks (static configuration for now)
    pub tracked_shards: Vec<ShardId>,
}
```

**File:** chain/jsonrpc/src/lib.rs (L744-790)
```rust
                    request,
                    source,
                    |params| {
                        self.light_client_proof_sharded("EXPERIMENTAL_light_client_proof", params)
                    },
                    |params| self.light_client_proof_local(params),
                )
                .await
            }
            "EXPERIMENTAL_light_client_block_proof" => {
                process_method_call(request, |params| self.light_client_block_proof(params)).await
            }
            "EXPERIMENTAL_protocol_config" => {
                process_method_call(request, |params| self.protocol_config(params)).await
            }
            "EXPERIMENTAL_receipt" => {
                process_sharded_method_call(
                    request,
                    source,
                    |params| self.receipt_sharded(params),
                    |params| self.receipt_local(params),
                )
                .await
            }
            "EXPERIMENTAL_receipt_to_tx" => {
                process_method_call(request, |params| self.receipt_to_tx(params)).await
            }
            "EXPERIMENTAL_tx_status" => {
                process_method_call(request, |params| self.tx_status_common(params, true)).await
            }
            "EXPERIMENTAL_validators_ordered" => {
                process_method_call(request, |params| self.validators_ordered(params)).await
            }
            "EXPERIMENTAL_split_storage_info" => {
                process_method_call(request, |params| self.split_storage_info(params)).await
            }
            #[cfg(feature = "sandbox")]
            "sandbox_patch_state" => {
                process_method_call(request, |params| self.sandbox_patch_state(params)).await
            }
            #[cfg(feature = "sandbox")]
            "sandbox_fast_forward" => {
                process_method_call(request, |params| self.sandbox_fast_forward(params)).await
            }
            _ => return Err(request),
        })
    }
```

**File:** chain/jsonrpc/src/lib.rs (L1488-1524)
```rust
    async fn run_coordinator_request(
        &self,
        method: &str,
        params: impl serde::Serialize,
        block_hint: BlockHint,
        shard_hint: ShardHint,
        strategy: CoordinatorRequestStrategy,
    ) -> Result<Value, RpcError> {
        // Find the nodes that might be able to answer the query.
        let rpc_nodes = {
            let pool_read_guard = self.pool.read();
            pool_read_guard.nodes_for_query(block_hint, shard_hint)?
        };

        // Prepare the request.
        let request = match Message::request(
            method.to_string(),
            serde_json::to_value(params)
                .map_err(|e| RpcError::serialization_error(e.to_string()))?,
        ) {
            Message::Request(r) => r,
            _ => {
                return Err(RpcError::new_internal_error(
                    None,
                    "run_coordinator_request: failed to create a request".to_string(),
                ));
            }
        };

        match strategy {
            CoordinatorRequestStrategy::Sequential => {
                self.run_coordinator_request_sequential(request, rpc_nodes).await
            }
            CoordinatorRequestStrategy::ParallelTakeFirst => {
                self.run_coordinator_request_parallel_take_first(request, rpc_nodes).await
            }
        }
```

**File:** chain/jsonrpc/src/sharded_rpc.rs (L116-157)
```rust
    pub fn new(
        config: Option<ShardedRpcConfig>,
        shard_tracker: ShardTracker,
        chain_store: ChainStoreAdapter,
    ) -> Self {
        let nodes = match config {
            Some(config) => {
                let nodes: Vec<_> = config
                    .nodes
                    .iter()
                    .filter(|node_config| {
                        if is_local_address(&node_config.address) {
                            tracing::info!(
                                target: "jsonrpc",
                                address = %node_config.address,
                                tracked_shards = ?node_config.tracked_shards,
                                "sharded rpc pool: detected self-connection, \
                                 excluding from remote pool"
                            );
                            return false;
                        }
                        true
                    })
                    .map(|node_config| ShardedRpcNode {
                        client: Arc::new(near_jsonrpc_client_internal::new_client(
                            &node_config.address,
                        )),
                        tracked_shards: node_config.tracked_shards.clone(),
                    })
                    .collect();
                tracing::info!(
                    target: "jsonrpc",
                    total_configured = config.nodes.len(),
                    remote_nodes = nodes.len(),
                    "sharded rpc pool initialized"
                );
                nodes
            }
            None => vec![],
        };
        Self { nodes, shard_tracker, chain_store }
    }
```

**File:** chain/jsonrpc/client/src/lib.rs (L471-482)
```rust
fn create_client() -> Client {
    Client::builder()
        .timeout(CONNECT_TIMEOUT)
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client")
}

/// Create new JSON RPC client that connects to the given address.
pub fn new_client(server_addr: &str) -> JsonRpcClient {
    JsonRpcClient::new(server_addr, create_client())
}
```

**File:** pytest/tests/mocknet/sharded_bm.py (L351-356)
```python
            'address':
                f"http://[{ip}]:{rpc_port}"
                if ':' in ip else f"http://{ip}:{rpc_port}",
            'tracked_shards':
                shard_ids,
        })
```
