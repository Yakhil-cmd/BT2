[1](#0-0)

### Citations

**File:** crates/sui-core/src/authority/execution_time_estimator.rs (L68-80)
```rust
// Collects local execution time estimates to share via consensus.
pub struct ExecutionTimeObserver {
    epoch_store: Weak<AuthorityPerEpochStore>,
    consensus_adapter: Box<dyn SubmitToConsensus>,

    protocol_params: ExecutionTimeEstimateParams,
    config: ExecutionTimeObserverConfig,

    local_observations: LruCache<ExecutionTimeObservationKey, LocalObservations>,

    // For each object, tracks the amount of time above our utilization target that we spent
    // executing transactions. This is used to decide which observations should be shared
    // via consensus.
```
