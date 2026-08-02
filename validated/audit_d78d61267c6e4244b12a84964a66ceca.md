[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** mempool/src/shared_mempool/types.rs (L110-204)
```rust






























































































impl fmt::Display for QuorumStoreRequest {
```

**File:** mempool/src/shared_mempool/network.rs (L75-106)
```rust































#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
```

**File:** mempool/src/shared_mempool/network.rs (L298-315)
```rust
    pub fn process_broadcast_ack(
        &self,
        peer: PeerNetworkId,
        message_id: MempoolMessageId,
        retry: bool,
        backoff: bool,
        timestamp: SystemTime,
    ) {
        let mut sync_states = self.sync_states.write();

        let sync_state = if let Some(state) = sync_states.get_mut(&peer) {
            state
        } else {
            counters::invalid_ack_inc(peer.network_id(), counters::UNKNOWN_PEER);
            return;
        };

        if let Some(sent_timestamp) = sync_state.broadcast_info.sent_messages.remove(&message_id) {
```

**File:** mempool/src/shared_mempool/network.rs (L461-468)
```rust
                    let txns = message_id
                        .decode()
                        .into_iter()
                        .flat_map(|(sender_bucket, start_end_pairs)| {
                            if self.node_type.is_validator() {
                                mempool
                                    .timeline_range(sender_bucket, start_end_pairs)
                                    .into_iter()
```
