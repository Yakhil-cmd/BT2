No vulnerability found for this question.

**Reasoning:** `SecretShareMetadata` and `secret_share_store.rs` belong entirely to the consensus randomness-beacon (secret sharing) subsystem, not the transaction admission path (mempool/vm-validator/API/authenticator) [1](#0-0) . Shares are collected in a `BTreeMap<Round, SecretShareItem>` keyed only by round [2](#0-1) , but every insertion path (`add_share`, `add_share_with_metadata`) explicitly checks full-struct equality `metadata == &share.metadata` before merging a share into the aggregator's bucket [3](#0-2) , so shares with matching round/epoch but differing `block_id`/`digest` are rejected rather than merged — the premise that only a subset of fields is compared upstream doesn't hold in this code path.

Beyond that correctness point, this code is populated by validator-to-validator broadcast messages (reliable broadcast in `consensus/src/rand/secret_sharing/reliable_broadcast_state.rs`), not by unprivileged transaction, authenticator, REST/BCS API, or proof input as required by the Boundary Conditions, and peer-driven consensus scenarios are explicitly out of scope for this review.

### Citations

**File:** types/src/secret_sharing.rs (L32-39)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq, Hash)]
pub struct SecretShareMetadata {
    pub epoch: u64,
    pub round: Round,
    pub timestamp: u64,
    pub block_id: HashValue,
    pub digest: Digest,
}
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L217-238)
```rust
            SecretShareItem::PendingDecision {
                metadata,
                share_aggregator,
            } => {
                ensure!(
                    metadata == &share.metadata,
                    "[SecretShareItem] SecretShare metadata from {} mismatch with block metadata!",
                    share.author,
                );
                share_aggregator.add_share(share, share_weight);
                Ok(())
            },
            SecretShareItem::Aggregating {
                metadata,
                pending_shares,
                ..
            } => {
                ensure!(
                    metadata == &share.metadata,
                    "[SecretShareItem] SecretShare metadata from {} mismatch with block metadata!",
                    share.author,
                );
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L403-410)
```rust
pub struct SecretShareStore {
    epoch: u64,
    self_author: Author,
    verifier: Arc<SecretShareVerifier>,
    secret_share_map: BTreeMap<Round, SecretShareItem>,
    highest_known_round: u64,
    decision_tx: Sender<SecretShareAggregationResult>,
}
```
