### No vulnerability found for this question.

The target function `BandwidthRequests::empty()` is a trivial, argument-free constructor that simply returns `BandwidthRequests::V1(BandwidthRequestsV1 { requests: Vec::new() })` [1](#0-0) . It takes no attacker-controlled input, performs no arithmetic, indexing, or unwrapping, and therefore has no code path through which an unprivileged attacker's request sets (empty, maximal, or duplicated) could drive it to panic. The actual scheduling logic that processes attacker-influenced `BandwidthRequest`/`BandwidthRequestsV1` data lives in `runtime/runtime/src/bandwidth_scheduler/scheduler.rs` (`BandwidthScheduler::run`, `schedule_bandwidth`, `SchedulerBandwidthRequest::new`, etc.) [2](#0-1) [3](#0-2) , not in `empty`. Since the question specifically targets `bandwidth_scheduler.rs::empty` as the panic site, and that function cannot panic regardless of attacker input, the premise does not hold.

### Citations

**File:** core/primitives/src/bandwidth_scheduler.rs (L35-39)
```rust
impl BandwidthRequests {
    pub fn empty() -> BandwidthRequests {
        BandwidthRequests::V1(BandwidthRequestsV1 { requests: Vec::new() })
    }
}
```

**File:** runtime/runtime/src/bandwidth_scheduler/scheduler.rs (L199-311)
```rust
impl BandwidthScheduler {
    pub fn run(
        shard_layout: ShardLayout,
        state: &mut BandwidthSchedulerState,
        params: &BandwidthSchedulerParams,
        bandwidth_requests: &BlockBandwidthRequests,
        shards_status: &BTreeMap<ShardId, ShardStatus>,
        rng_seed: [u8; 32],
    ) -> GrantedBandwidth {
        if shard_layout.num_shards() == 0 {
            // No shards, nothing to grant.
            return GrantedBandwidth { granted: BTreeMap::new() };
        }

        let state = match state {
            BandwidthSchedulerState::V1(v1) => v1,
        };

        // Convert link allowances to the internal representation.
        let mut link_allowances: ShardLinkMap<Bandwidth> = ShardLinkMap::new(&shard_layout);
        for link_allowance in &state.link_allowances {
            let sender_index_opt = shard_layout.get_shard_index(link_allowance.sender);
            let receiver_index_opt = shard_layout.get_shard_index(link_allowance.receiver);
            match (sender_index_opt, receiver_index_opt) {
                (Ok(sender_index), Ok(receiver_index)) => {
                    let link = ShardLink::new(sender_index, receiver_index);
                    link_allowances.insert(link, link_allowance.allowance);
                }
                _ => {} // The allowance was for a shard that is not in the current set of shards. // TODO(bandwidth_scheduler) - add a warning?
            }
        }

        // Initialize the allowed link map based on shard statuses
        let mut shard_status_by_index: ShardIndexMap<ShardStatus> =
            ShardIndexMap::new(&shard_layout);
        for (shard_id, status) in shards_status {
            if let Ok(idx) = shard_layout.get_shard_index(*shard_id) {
                shard_status_by_index.insert(idx, *status);
            }
        }

        let mut is_link_allowed_map: ShardLinkMap<bool> = ShardLinkMap::new(&shard_layout);
        for sender_index in shard_layout.shard_indexes() {
            for receiver_index in shard_layout.shard_indexes() {
                let is_allowed = Self::calculate_is_link_allowed(
                    sender_index,
                    receiver_index,
                    &shard_status_by_index,
                );
                is_link_allowed_map
                    .insert(ShardLink::new(sender_index, receiver_index), is_allowed);
            }
        }

        // Convert bandwidth requests to representation used in the algorithm.
        let mut scheduler_bandwidth_requests: Vec<SchedulerBandwidthRequest> = Vec::new();
        for (sender_shard, shard_bandwidth_requests) in
            &bandwidth_requests.shards_bandwidth_requests
        {
            let requests = match shard_bandwidth_requests {
                BandwidthRequests::V1(requests_v1) => &requests_v1.requests,
            };

            for bandwidth_request in requests {
                // Convert request to the internal representation. It might turn out that the
                // request isn't applicable (e.g. shard ids from other layout, too little bandwidth
                // requested), in which case the function returns `None` and the request is ignored.
                // TODO(bandwidth_scheduler) - add a warning?
                if let Some(request) = SchedulerBandwidthRequest::new(
                    *sender_shard,
                    bandwidth_request,
                    params,
                    &shard_layout,
                ) {
                    scheduler_bandwidth_requests.push(request);
                }
            }
        }

        let sender_budget = ShardIndexMap::new(&shard_layout);
        let receiver_budget = ShardIndexMap::new(&shard_layout);
        let granted_bandwidth = ShardLinkMap::new(&shard_layout);

        // Init the scheduler state
        let mut scheduler = BandwidthScheduler {
            shard_layout,
            is_link_allowed_map,
            sender_budget,
            receiver_budget,
            link_allowances,
            granted_bandwidth,
            params: *params,
            rng: ChaCha20Rng::from_seed(rng_seed),
        };

        // Run the core algorithm
        let grants = scheduler.schedule_bandwidth(scheduler_bandwidth_requests);

        // Update the persistent scheduler state
        scheduler.update_scheduler_state(state);

        grants
    }

    fn schedule_bandwidth(&mut self, requests: Vec<SchedulerBandwidthRequest>) -> GrantedBandwidth {
        self.init_budgets();
        self.increase_allowances();
        self.grant_base_bandwidth();
        self.process_bandwidth_requests(requests);
        self.distribute_remaining_bandwidth();

        self.get_final_granted_bandwidth()
    }
```

**File:** runtime/runtime/src/bandwidth_scheduler/scheduler.rs (L598-643)
```rust
impl SchedulerBandwidthRequest {
    pub fn new(
        sender_shard: ShardId,
        bandwidth_request: &BandwidthRequest,
        params: &BandwidthSchedulerParams,
        layout: &ShardLayout,
    ) -> Option<Self> {
        let Ok(sender_index) = layout.get_shard_index(sender_shard) else {
            // Request from a shard that is not in the current set of shards.
            return None;
        };
        let Ok(receiver_index) = layout.get_shard_index(bandwidth_request.to_shard.into()) else {
            // Request to a shard that is not in the current set of shards.
            return None;
        };
        let link = ShardLink::new(sender_index, receiver_index);

        let mut bandwidth_increases = VecDeque::new();

        // Keeps track of the total bandwidth that would be granted by the requested increases.
        // Base bandwidth is already granted on all links, so we start with that.
        let mut current_total = params.base_bandwidth;

        let request_values = BandwidthRequestValues::new(params).values;
        for bit_idx in 0..bandwidth_request.requested_values_bitmap.len() {
            if !bandwidth_request.requested_values_bitmap.get_bit(bit_idx) {
                continue;
            }

            // Request for the total value of bandwidth that should be granted on the link.
            let requested_value = request_values[bit_idx];
            if requested_value <= current_total {
                continue;
            }
            // Convert the absolute value to a bandwidth increase.
            bandwidth_increases.push_back(requested_value - current_total);
            current_total = requested_value;
        }

        if bandwidth_increases.is_empty() {
            return None;
        }

        Some(Self { link, bandwidth_increases })
    }
}
```
