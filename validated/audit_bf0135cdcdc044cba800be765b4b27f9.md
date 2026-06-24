Audit Report

## Title
Missing Concurrency Cap in `call_sync` Enables HTTP Connection Hold and Unbounded `IngressWatcher` State Growth — (File: `rs/http_endpoints/public/src/call/call_sync.rs`)

## Summary

The synchronous call handler (`call_sync`) holds each HTTP connection open while awaiting `wait_for_certification()` with no concurrency limit, unlike the asynchronous handler which uses a `Semaphore` to bound concurrent tracking tasks. The `IngressWatcher` backing both handlers stores per-message state in an uncapped `HashMap` and `JoinMap`. An unprivileged attacker flooding the `/api/v3` or `/api/v4` sync endpoints with valid, unique ingress messages can exhaust HTTP connection resources and grow `IngressWatcher` internal state, degrading service for all replica users.

## Finding Description

**Root cause 1 — No concurrency cap in `call_sync`:**

`call_sync` blocks the HTTP connection at `wait_for_certification().timeout(...)` with no guard: [1](#0-0) 

By contrast, `call_async` uses a `Semaphore` with `MAX_CONCURRENT_TRACKING_TASKS = 10_000` to bound concurrent background tracking tasks, and returns `202 Accepted` immediately to the caller: [2](#0-1) 

In `call_sync` there is no equivalent guard — the HTTP connection itself is held open for up to `ingress_message_certificate_timeout_seconds` per request, with no ceiling on how many can be simultaneously waiting.

**Root cause 2 — Unbounded `IngressWatcher` state:**

`IngressWatcher` stores per-message state in an uncapped `HashMap` and `JoinMap`: [3](#0-2) 

`handle_ingress_message` inserts into both structures for every new unique message with no size check: [4](#0-3) 

The subscription channel is bounded at 1000 entries: [5](#0-4) 

However, once a subscription is dequeued and processed by the event loop, the entry lives in the unbounded `message_statuses` HashMap until the message is certified or the subscriber drops (i.e., until the connection timeout fires). The channel bound only limits the rate of ingestion, not the total accumulated state.

**Exploit flow:**

1. Attacker holds a valid identity and generates N unique ingress messages (distinct nonces/expiry combinations).
2. Each message passes `validate_ingress_message` (signature valid, expiry valid, ingress pool not yet full).
3. `subscribe_for_certification` is called, inserting an entry into `message_statuses` and spawning a task in `cancellations`.
4. `try_submit()` succeeds, placing the message in the ingress pool.
5. The connection blocks at `wait_for_certification().timeout(ingress_message_certificate_timeout_seconds)`.
6. With N concurrent requests, N connections are held open simultaneously, and `message_statuses` / `cancellations` grow to N entries.
7. The ingress pool throttle (~10,000 messages) bounds N in steady state, but the attacker can rotate messages (using expiry cycling) to sustain the attack continuously.

**Existing guards and why they are insufficient:**

- *Ingress pool throttling*: Rejects messages when the pool is full, bounding the number of simultaneously held connections to roughly the pool size (~10,000). This does not prevent the attack — it only caps the instantaneous scale. The attacker can sustain the pool at capacity continuously.
- *Subscription channel backpressure (1000 entries)*: Limits the rate of new subscriptions but not the total accumulated `message_statuses` size, which grows as the event loop drains the channel.
- *`SUBSCRIPTION_TIMEOUT` (1 s)*: If the channel is full, new subscriptions time out and return `202 Accepted` quickly. This limits the rate of new connection holds but does not cap the number already waiting.

## Impact Explanation

An attacker sustaining the ingress pool at capacity (~10,000 messages) holds ~10,000 HTTP connections open simultaneously for the full `ingress_message_certificate_timeout_seconds` window. This constitutes an **application/platform-level DoS** against the replica's public API: legitimate users' connections are crowded out, and the `IngressWatcher` event loop's per-iteration work (polling `cancellations.join_next()`, iterating `completed_execution_heights`) increases with state size, delaying certification notifications for all subscribers. This matches the allowed High impact: *"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."*

## Likelihood Explanation

Any unprivileged user with a valid identity can execute this attack. Generating thousands of unique valid ingress messages (varying nonce/expiry) is straightforward with standard IC agent tooling. No key compromise, governance majority, or privileged access is required. The ingress pool size (~10,000) provides a natural scale bound but does not prevent the attack — the attacker simply keeps the pool saturated. The attack is repeatable and sustainable.

## Recommendation

1. **Add a concurrency limit to `call_sync`**: Introduce a `Semaphore` (analogous to `MAX_CONCURRENT_TRACKING_TASKS` in `call_async.rs`) in `SynchronousCallHandlerState`. When no permit is available, return `202 Accepted` immediately instead of blocking the connection.
2. **Cap `IngressWatcher.message_statuses`**: Enforce a maximum size on the `message_statuses` HashMap. When the cap is reached, return `SubscriptionError` from `handle_ingress_message` so `call_sync` falls back to `202 Accepted`.
3. **Reduce `ingress_message_certificate_timeout_seconds`**: A shorter timeout reduces the window during which connections are held open, limiting the maximum concurrent connection count.

## Proof of Concept

```rust
// Integration test sketch (PocketIC or local replica):
// 1. Spawn a local replica with a short ingress_message_certificate_timeout_seconds (e.g., 30s).
// 2. Generate MAX_POOL_SIZE unique ingress messages (distinct nonces) signed by a test identity.
// 3. Send all requests concurrently to /api/v3/canister/<id>/call.
// 4. Assert: all connections remain open (no response yet) for ~timeout duration.
// 5. Assert: IngressWatcher metrics `ingress_watcher_tracked_messages` == MAX_POOL_SIZE.
// 6. Assert: new legitimate requests to /api/v3 receive no timely response (connection backlog).
// 7. After timeout, all connections return 202 Accepted and metrics drop to 0.

// Shell PoC:
for i in $(seq 1 10000); do
  curl -s -X POST https://<replica>/api/v3/canister/<canister-id>/call \
    -H "Content-Type: application/cbor" \
    --data-binary @<valid_ingress_cbor_unique_nonce_$i> &
done
wait
# Observe: ~10000 open connections held for full timeout; legitimate requests time out.
```

### Citations

**File:** rs/http_endpoints/public/src/call/call_sync.rs (L310-327)
```rust
    match certification_subscriber
        .wait_for_certification()
        .timeout(Duration::from_secs(
            ingress_message_certificate_timeout_seconds,
        ))
        .await
    {
        Ok(()) => (),
        Err(_) => {
            metrics
                .sync_call_early_response_trigger_total
                .with_label_values(&[SYNC_CALL_EARLY_RESPONSE_CERTIFICATION_TIMEOUT])
                .inc();
            return SyncCallResponse::Accepted(
                "Message did not complete execution and certification within the replica defined timeout.",
            );
        }
    }
```

**File:** rs/http_endpoints/public/src/call/call_async.rs (L30-52)
```rust
/// Used to bound the number of tokio tasks spawned for tracking the
/// certification time of messages. 10_000 is chosen as it is roughly
/// the pool size.
const MAX_CONCURRENT_TRACKING_TASKS: usize = 10_000;

#[derive(Clone)]
pub struct AsynchronousCallHandlerState {
    ingress_watcher_handle: Option<IngressWatcherHandle>,
    ingress_validator: IngressValidator,
    ingress_tracking_semaphore: Arc<Semaphore>,
}

impl AsynchronousCallHandlerState {
    pub fn new(
        ingress_validator: IngressValidator,
        ingress_watcher_handle: Option<IngressWatcherHandle>,
    ) -> Self {
        Self {
            ingress_validator,
            ingress_watcher_handle,
            ingress_tracking_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TRACKING_TASKS)),
        }
    }
```

**File:** rs/http_endpoints/public/src/call/ingress_watcher.rs (L22-22)
```rust
const INGRESS_WATCHER_CHANNEL_SIZE: usize = 1000;
```

**File:** rs/http_endpoints/public/src/call/ingress_watcher.rs (L119-133)
```rust
pub struct IngressWatcher {
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    rt_handle: Handle,
    cancellation_token: CancellationToken,
    /// Keeps track of the certified height.
    certified_height: Height,

    /// Maps message id to a future that resolves when all subscribers stop waiting for its certification.
    cancellations: JoinMap<MessageId, ()>,
    /// Maps the message id to its [`MessageExecutionStatus`] and a [`Notify`]er to notify its subscribers when the message is certified.
    message_statuses: HashMap<MessageId, (MessageExecutionStatus, Arc<Notify>)>,
    /// Inverse index, maps the height to the set of message ids that completed execution at that height.
    completed_execution_heights: BTreeMap<Height, HashSet<MessageId>>,
}
```

**File:** rs/http_endpoints/public/src/call/ingress_watcher.rs (L287-302)
```rust
        let certification_notifier = match self.message_statuses.entry(message.clone()) {
            // New message, create a new notifier.
            Entry::Vacant(vacant_entry) => {
                self.cancellations.spawn_on(
                    message.clone(),
                    cancellation_token.cancelled_owned(),
                    &self.rt_handle,
                );

                let certification_notifier = Arc::new(tokio::sync::Notify::new());
                vacant_entry.insert((
                    MessageExecutionStatus::InProgress,
                    certification_notifier.clone(),
                ));

                Ok(certification_notifier)
```
