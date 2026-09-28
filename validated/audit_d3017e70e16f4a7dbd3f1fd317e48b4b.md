### Title
Archived spoke usage rows reset supply/borrow caps to zero, letting unprivileged users exceed configured caps - (File: contracts/controller/src/spoke_usage.rs)

### Summary
`x/crosschain`'s `InitGenesis` bug is "absent state silently reads as zero": pending nonces that were really non-zero were re-initialized to 0, and every subsequent accounting check ran against the zeroed value. XOXNO Lending has the same shape in spoke usage accounting. `SpokeUsage` rows are held in **persistent** storage (`ControllerKey::SpokeUsage`), and every read path treats `None` — which is indistinguishable from "archived after TTL expiry" — as a legitimately zero row. A supply or borrow on a spoke/asset pair whose usage row archived re-starts cap accounting at zero, so the configured `supply_cap`/`borrow_cap` is silently bypassed.

### Finding Description
`storage::get_spoke_usage` returns `Option<SpokeUsageRaw>` from persistent storage and only renews TTL **when the entry exists** (`get_shared` renews on `is_some`). Once a `SpokeUsage(spoke_id, hub_asset)` entry is archived (a spoke/asset pair with no user flow for the shared TTL window), the entry is gone until a restore.

The unprivileged-reachable paths then treat the missing row as zero:

- `SpokeUsageContext::apply_entry` — reached from `supply` and `borrow` — does `self.load_usage_row(hub_asset).unwrap_or_default()`, so the cap check `enforce_spoke_cap` computes `next_scaled = 0 + delta_scaled` and compares only against `cap_scaled`. Any amount up to the full cap is accepted regardless of the real outstanding usage.
- `SpokeUsageContext::apply_exit` — reached from `withdraw`/`repay` — is a documented no-op on a missing row, so the real usage is never re-decremented; post-restore the row is stale on top of having been bypassed.
- `set_spoke_usage` physically deletes the row whenever both sides hit zero, which is correct only because callers are trusted to have loaded the row first — after archival they don't.

This is directly analogous to `NonceHigh` being reset to 0 while the true chain nonce was non-zero: the equality/cap check runs against a fabricated zero baseline.

### Impact Explanation
Spoke supply/borrow caps are the per-spoke risk limits. An unprivileged borrower who waits for (or finds) a spoke/asset usage row past its archival point can call `borrow` with an `amount` up to the full `borrow_cap` even though the spoke's real outstanding usage is already at or near the cap — and repeat this each time the re-written row lapses again, cumulatively exceeding the intended cap. Likewise `supply` can exceed `supply_cap`. Unbounded over-borrowing against capped risk parameters exposes the pool to utilization and collateral levels governance explicitly disallowed, i.e., protocol insolvency risk. Additionally, an archived usage row makes `remove_asset_from_spoke` see `unwrap_or_default()` zero usage and pass `SpokeAssetInUse` check while real positions exist — asset delisting over live positions, freezing user accounting (governance call, but the zero-read is the same root cause).

### Likelihood Explanation
Requires the persistent `SpokeUsage` entry to archive without any operation renewing it (no supply/borrow/withdraw/repay on that spoke/asset for the TTL window). Plausible for low-activity listings, and archival is a normal Soroban state transition, not an attack on the oracle or admin. Reachable by any address via `Controller::supply`/`Controller::borrow`; no privileged role needed.

### Recommendation
Do not treat a missing `SpokeUsage` row as equivalent to zero in cap checks. Either (a) restore-or-fail: in `apply_entry`, `panic_with_error!` (e.g., `SpokeError::SpokeUsageArchived`) when `get_spoke_usage` returns `None` while the spoke asset config shows live caps, or (b) keep usage in instance/non-archivable storage, or (c) extend TTL on both read-hit and read-miss paths plus a periodic keeper bump. Same fix as the ZetaChain report: never reconstruct live counters from an absent-default.

### Proof of Concept
1. Governance lists asset A in spoke S with `borrow_cap = C`; users borrow up to `C` so `SpokeUsage(S, A).borrowed_scaled_ray ≈ scaled(C)`.
2. No flow touches `(S, A)` until the persistent `SpokeUsage` entry archives (ledger sequence advances past its TTL; equivalent to `env.storage().persistent().remove(&ControllerKey::SpokeUsage(S, hubA))` in a test harness).
3. Attacker calls `controller.borrow(account_id, vec![(hubA, C)])`. `apply_entry` → `load_usage_row` returns `None` → `unwrap_or_default()` → `enforce_spoke_cap` computes `0 + scaled(C) <= scaled(C)` → passes. Total spoke usage is now `2·C`, double the configured cap.
4. In `contracts/controller/tests/spoke.rs` terms: seed usage, remove the `SpokeUsage` key directly, then `apply_entry(UsageSide::Borrow, …, cap, index, decimals)` with `delta_scaled` at the cap — assert it does not panic with `SpokeBorrowCapReached` (it should).