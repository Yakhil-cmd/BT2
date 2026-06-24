All cited code is confirmed in the repository. Let me verify the arithmetic and the full exploit path before rendering a verdict.

**Confirmed facts from the code:**

1. `Time::from_duration` at `rs/types/types/src/time.rs` L103-104 does `Time(t.as_nanos() as u64)` — a silent truncating cast from `u128` to `u64`. [1](#0-0) 

2. `AddAssign` at L55-58 calls `from_duration`. [2](#0-1) 

3. `interval = 300s − 60s − 120s = 120s = 120_000_000_000 ns`. [3](#0-2) 

4. The loop at L99-107 uses `now += interval` with no overflow guard. [4](#0-3) 

5. `ingress_start` and `ingress_end` are accepted as raw `u64` with no range validation. [5](#0-4) 

6. ICRC1 has `ingress_start >= ingress_end` guard; ICP Rosetta has none. [6](#0-5) 

**Arithmetic verification:**

With `ingress_start = u64::MAX − 120_000_000_000 + 1`:
- `Duration::from_nanos(ingress_start) + Duration::from_nanos(120_000_000_000)` = Duration of ~18,446,744,193 seconds — valid for `Duration` (which stores seconds as `u64`, max ~584 years).
- `as_nanos()` returns `u128`: `18_446_744_193_589_551_616` — exceeds `u64::MAX` (`18_446_744_073_709_551_615`).
- `as u64` truncates: `18_446_744_193_589_551_616 mod 2^64 = 119_880_000_000` (~120 s since epoch).
- Loop then runs from `~120_000_000_000` to `u64::MAX` in 120s steps: ≈ `153,722,867,280` iterations, each pushing 8 bytes → OOM.

All claims check out. The `checked_add` safe alternative already exists at L122-128 but is not used by `AddAssign`. [7](#0-6) 

---

Audit Report

## Title
Unbounded `ingress_expiries` vector growth via silent `u64` truncation in `Time::AddAssign` — (`rs/rosetta-api/icp/src/request_handler/construction_payloads.rs`)

## Summary

`Time::AddAssign` delegates to `Time::from_duration`, which casts `Duration::as_nanos()` (a `u128`) to `u64` with a bare `as` truncating cast. When `ingress_start` is set near `u64::MAX` and `ingress_end = u64::MAX`, the first `now += interval` in the `construction_payloads` ingress-expiry loop wraps `now` to ~120 seconds since the Unix epoch, causing the loop to iterate ~153 billion times and exhaust process memory, crashing the ICP Rosetta node.

## Finding Description

`construction_payloads` in `rs/rosetta-api/icp/src/request_handler/construction_payloads.rs` accepts caller-controlled `ingress_start` and `ingress_end` as raw `u64` nanosecond timestamps with no range validation (L74–84). The loop at L99–107 advances `now` by `interval` (120 s) each iteration via `now += interval`, which invokes `Time::AddAssign` (L55–58 of `rs/types/types/src/time.rs`). `AddAssign` calls `Time::from_duration(Duration::from_nanos(self.0) + other)`, and `from_duration` (L103–104) performs `Time(t.as_nanos() as u64)` — a silent truncating cast.

With `ingress_start = u64::MAX − 120_000_000_000 + 1` and `ingress_end = u64::MAX`:
- Iteration 1: `now` is near `u64::MAX`, condition `now < ingress_end` is true, push, then `now += interval` produces a `Duration` of ~18,446,744,193 seconds whose `as_nanos()` value (`18_446_744_193_589_551_616`) exceeds `u64::MAX`. The `as u64` cast truncates to `119_880_000_000` (~120 s since epoch).
- Iterations 2+: `now ≈ 120e9 << ingress_end = u64::MAX`, so the loop runs ≈ `u64::MAX / 120e9 ≈ 153,722,867,280` more times, each pushing a `u64` onto the heap.

The safe `Time::checked_add` (L122–128) already exists and handles this correctly, but `AddAssign` does not use it. The ICRC1 Rosetta counterpart (`rs/rosetta-api/icrc1/src/construction_api/services.rs` L148–158) has explicit guards (`ingress_start >= ingress_end`) that the ICP Rosetta path entirely lacks.

## Impact Explanation

The Rosetta node process exhausts virtual memory and is killed by the OS OOM killer after a single request. This takes the ICP Rosetta node fully offline, blocking all ICP ledger integrations (exchanges, custodians, wallets) that depend on it. This matches the allowed High impact: **"Application/platform-level DoS, crash … or subnet availability impact not based on raw volumetric DDoS"** and **"Significant … Rosetta … security impact with concrete user or protocol harm."** Severity: **High ($2,000–$10,000)**.

## Likelihood Explanation

The `/construction/payloads` endpoint is public and unauthenticated. The trigger value (`ingress_start = u64::MAX − 120_000_000_000 + 1`) is trivially computed. No special privileges, keys, or network position are required. The attack is a single JSON HTTP POST and is immediately repeatable after any restart of the node.

## Recommendation

1. Replace the bare `as u64` cast in `Time::from_duration` with a checked conversion (matching the pattern already used in `Time::checked_add`, `checked_sub`, and `saturating_sub`), or make `AddAssign` use `checked_add` and panic/saturate on overflow.
2. Add input validation in `construction_payloads` mirroring the ICRC1 version: reject requests where `ingress_start >= ingress_end`, and cap `(ingress_end − ingress_start) / interval` to a small constant (e.g., 1440).
3. Cap the `ingress_expiries` vector to a maximum size and return an error if the computed range would exceed it.

## Proof of Concept

```
POST /construction/payloads
{
  "network_identifier": { ... },
  "operations": [ <valid transfer op> ],
  "public_keys": [ <valid pk> ],
  "metadata": {
    "ingress_start": 18446744073589551616,
    "ingress_end":   18446744073709551615
  }
}
```

After one loop iteration `now` wraps to `119_880_000_000`. The loop then runs ≈ 153 billion more iterations, each appending 8 bytes to `ingress_expiries`. The process is OOM-killed within seconds. A unit test can confirm the wrap: `assert!(Time::from_nanos_since_unix_epoch(u64::MAX - 120_000_000_000 + 1).checked_add(Duration::from_nanos(120_000_000_000)).is_none())` passes, while `let mut t = Time::from_nanos_since_unix_epoch(u64::MAX - 120_000_000_000 + 1); t += Duration::from_nanos(120_000_000_000); assert!(t.as_nanos_since_unix_epoch() < 200_000_000_000)` demonstrates the wrap.

### Citations

**File:** rs/types/types/src/time.rs (L55-58)
```rust
impl std::ops::AddAssign<Duration> for Time {
    fn add_assign(&mut self, other: Duration) {
        *self = Time::from_duration(Duration::from_nanos(self.0) + other)
    }
```

**File:** rs/types/types/src/time.rs (L102-105)
```rust
    /// A private function to cast from [Duration] to [Time].
    fn from_duration(t: Duration) -> Self {
        Time(t.as_nanos() as u64)
    }
```

**File:** rs/types/types/src/time.rs (L122-128)
```rust
    pub fn checked_add(self, rhs: Duration) -> Option<Time> {
        if let Ok(rhs_nanos) = u64::try_from(rhs.as_nanos()) {
            Some(Time(self.0.checked_add(rhs_nanos)?))
        } else {
            None
        }
    }
```

**File:** rs/rosetta-api/icp/src/request_handler/construction_payloads.rs (L59-60)
```rust
        let interval =
            ic_limits::MAX_INGRESS_TTL - ic_limits::PERMITTED_DRIFT - Duration::from_secs(120);
```

**File:** rs/rosetta-api/icp/src/request_handler/construction_payloads.rs (L99-107)
```rust
        let mut ingress_expiries = vec![];
        let mut now = ingress_start;
        while now < ingress_end {
            let ingress_expiry = (now
                + ic_limits::MAX_INGRESS_TTL.saturating_sub(ic_limits::PERMITTED_DRIFT))
            .as_nanos_since_unix_epoch();
            ingress_expiries.push(ingress_expiry);
            now += interval;
        }
```

**File:** rs/rosetta-api/icp/src/models.rs (L199-223)
```rust
/// Typed metadata of ConstructionPayloadsRequest.
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct ConstructionPayloadsRequestMetadata {
    /// The memo to use for a ledger transfer.
    /// A random number is used by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<u64>,

    /// The earliest acceptable expiry date for a ledger transfer.
    /// Must be within 24 hours from created_at_time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_start: Option<u64>,

    /// The latest acceptable expiry date for a ledger transfer.
    /// Must be within 24 hours from created_at_time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_end: Option<u64>,

    /// If present, overrides ledger transaction creation time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_time: Option<u64>,
}
```

**File:** rs/rosetta-api/icrc1/src/construction_api/services.rs (L148-158)
```rust
    if ingress_start >= ingress_end {
        return Err(Error::processing_construction_failed(&format!(
            "Ingress start should start before ingress end: Start: {ingress_start}, End: {ingress_end}"
        )));
    }

    if ingress_end < now + ingress_interval {
        return Err(Error::processing_construction_failed(&format!(
            "Ingress end should be at least one interval from the current time: Current time: {now}, End: {ingress_end}"
        )));
    }
```
