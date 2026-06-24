Audit Report

## Title
Race Condition in Per-IP WebSocket Subscriber Limit Allows Limit Bypass — (`rs/boundary_node/ic_boundary/src/http/handlers.rs`)

## Summary
A TOCTOU race condition between `logs_canister` and `logs_canister_ws` in `handlers.rs` allows an attacker to establish more concurrent WebSocket connections from a single IP to a single canister log stream than `max_subscribers_per_ip_per_topic` permits. The root cause is that `ip_cache.get_with(...)` can return a stale `Arc<Mutex<u16>>` that has already been removed from the cache by a concurrent `ip_cache.invalidate(...)` call, causing two independent counter instances to each independently permit a new connection. This enables exhaustion of the global broker subscriber slots and denial of log access to all other clients.

## Finding Description
`LogsState` tracks per-`(IpAddr, Principal)` connection counts via a Moka cache mapping to `Arc<Mutex<u16>>` (line 47). In `logs_canister` (lines 97–124), the check-and-increment sequence is:

```rust
let counter = state.ip_cache.get_with((ip, canister_id), || Arc::new(Mutex::new(0)));
let sub = {
    let mut counter = counter.lock().unwrap();
    if *counter >= state.max_subscribers_per_ip_per_topic { return TOO_MANY_REQUESTS; }
    // subscribe + increment
    *counter += 1;
    sub
};
```

In `logs_canister_ws` (lines 183–188), teardown is:

```rust
let mut counter = counter.lock().unwrap();
*counter -= 1;
if *counter == 0 {
    state.ip_cache.invalidate(&(ip, canister_id));
}
```

**Exact race (with `max = 1`):**

1. Connection C0 is open. Cache: `(ip, cid) → Arc_A<Mutex<1>>`.
2. C0 closes. `logs_canister_ws` acquires the lock on `Arc_A`, decrements to `0`. Lock is **held**, counter = `0`, cache entry still present.
3. New connection **A** calls `get_with` — cache still has `Arc_A` — returns `Arc_A`. Tries `counter.lock()` — **blocks** because `logs_canister_ws` holds it.
4. `logs_canister_ws` calls `ip_cache.invalidate(...)`, removing `Arc_A` from the cache, then **releases the lock**.
5. New connection **B** calls `get_with` — cache is now **empty** — creates fresh `Arc_B<Mutex<0>>`, inserts it. Acquires lock, sees `0 < 1`, increments to `1`. **Connection B accepted.**
6. Connection **A** unblocks, acquires lock on `Arc_A`, sees `0 < 1` (decremented in step 2), increments to `1`. **Connection A also accepted.**

Both A and B are now open simultaneously, violating the limit of `1`. `Arc_A` is now orphaned (not in the cache). When connection A eventually closes, it calls `ip_cache.invalidate` on the key that now maps to `Arc_B`, evicting the live entry and corrupting accounting entirely.

The critical structural flaw: `get_with` returning an `Arc` and the subsequent `counter.lock()` are not atomic with respect to `invalidate`. Moka's `get_with` is atomic for concurrent init calls on the same key, but it provides no guarantee that the returned value is still the current cache entry by the time the caller uses it.

## Impact Explanation
An attacker can open arbitrarily many WebSocket connections from a single IP to a single canister's log stream, bypassing the per-IP rate limit (default 5). The only remaining backstop is the global `max_subscribers_per_topic` broker limit (default 1000). By monopolizing all 1000 broker subscriber slots from one IP, the attacker denies log access to all other clients and exhausts boundary node file descriptors and memory proportional to the number of open WebSocket connections. This constitutes an application/platform-level DoS against the boundary node's WebSocket API with concrete user harm, matching the High impact category: "Significant boundary/API... security impact with concrete user or protocol harm."

## Likelihood Explanation
The race window is small but reliably triggerable under concurrent load. The attacker fully controls the timing of connection teardown and new connection attempts. No authentication is required when `obs_log_websocket` is enabled; the endpoint is publicly reachable. A simple concurrent stress test (tight loop of close-then-connect from multiple goroutines) reliably hits this window. No special privileges, node access, or governance majority are required.

## Recommendation
The `get_with` call and the counter check/increment must be atomic with respect to `invalidate`. The correct fix is to replace the two-level structure (`Cache<key, Arc<Mutex<u16>>>`) with a single `DashMap` or `Mutex<HashMap>` so that lookup, check, increment, and invalidation all occur under one lock. Alternatively, never call `ip_cache.invalidate` from `logs_canister_ws`; instead configure Moka TTI/TTL to evict stale zero-count entries, and treat a cached counter value of `0` as equivalent to absent in `logs_canister`.

## Proof of Concept
```rust
// Concurrent stress test (max_subscribers_per_ip_per_topic = 1)
// 1. Open connection C0 (counter = 1)
// 2. Spawn simultaneously:
//    Task A: close C0 (decrement → 0 → hold lock → invalidate → release)
//    Task B: open C1 (get_with returns Arc_A → blocks on lock)
// 3. Immediately after Task A releases lock, spawn:
//    Task C: open C2 (get_with → cache empty → new Arc_B → counter=1 → accepted)
// 4. Task B unblocks: Arc_A counter=0 → increments to 1 → accepted
// Assert: C1 and C2 are both open simultaneously → limit violated
```

The existing sequential test at lines 347–364 already validates the happy path; a concurrent variant racing close and open at the exact boundary reproduces the bypass. The test infrastructure (tokio async, `tokio_tungstenite`) is already in place in the test module at line 299.