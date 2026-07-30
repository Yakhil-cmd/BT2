[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/sui-types/src/execution.rs (L320-335)
```rust
    pub fn from_command(command: &Command) -> Self {
        match command {
            Command::MoveCall(call) => ExecutionTimeObservationKey::MoveEntryPoint {
                package: call.package,
                module: call.module.clone(),
                function: call.function.clone(),
                type_arguments: vec![],
            },
            Command::TransferObjects(_, _) => ExecutionTimeObservationKey::TransferObjects,
            Command::SplitCoins(_, _) => ExecutionTimeObservationKey::SplitCoins,
            Command::MergeCoins(_, _) => ExecutionTimeObservationKey::MergeCoins,
            Command::Publish(_, _) => ExecutionTimeObservationKey::Publish,
            Command::MakeMoveVec(_, _) => ExecutionTimeObservationKey::MakeMoveVec,
            Command::Upgrade(_, _, _, _) => ExecutionTimeObservationKey::Upgrade,
        }
    }
```

**File:** crates/sui-types/src/execution.rs (L337-347)
```rust
    pub fn default_duration(&self) -> Duration {
        match self {
            ExecutionTimeObservationKey::MoveEntryPoint { .. } => Duration::from_millis(1),
            ExecutionTimeObservationKey::TransferObjects => Duration::from_millis(1),
            ExecutionTimeObservationKey::SplitCoins => Duration::from_millis(1),
            ExecutionTimeObservationKey::MergeCoins => Duration::from_millis(1),
            ExecutionTimeObservationKey::Publish => Duration::from_millis(3),
            ExecutionTimeObservationKey::MakeMoveVec => Duration::from_millis(1),
            ExecutionTimeObservationKey::Upgrade => Duration::from_millis(3),
        }
    }
```

**File:** crates/sui-core/src/authority/execution_time_estimator.rs (L69-104)
```rust
pub struct ExecutionTimeObserver {
    epoch_store: Weak<AuthorityPerEpochStore>,
    consensus_adapter: Box<dyn SubmitToConsensus>,

    protocol_params: ExecutionTimeEstimateParams,
    config: ExecutionTimeObserverConfig,

    local_observations: LruCache<ExecutionTimeObservationKey, LocalObservations>,

    // For each object, tracks the amount of time above our utilization target that we spent
    // executing transactions. This is used to decide which observations should be shared
    // via consensus.
    object_utilization_tracker: LruCache<ObjectID, ObjectUtilization>,

    // Sorted list of recently indebted objects, updated by consensus handler.
    indebted_objects: Vec<ObjectID>,

    sharing_rate_limiter: RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::MonotonicClock,
        governor::middleware::NoOpMiddleware<
            <governor::clock::MonotonicClock as governor::clock::Clock>::Instant,
        >,
    >,

    next_generation_number: u64,
}

#[derive(Debug, Clone)]
pub struct LocalObservations {
    moving_average: SingleSumSMA<Duration, u32, SMA_LOCAL_OBSERVATION_WINDOW_SIZE>,
    weighted_moving_average: WeightedMovingAverage,
    last_shared: Option<(Duration, Instant)>,
    config: ExecutionTimeObserverConfig,
}
```
