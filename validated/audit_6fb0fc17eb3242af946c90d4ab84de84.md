The code is confirmed. Let me verify the `reset_timers` function and compare with other guarded methods.

Audit Report

## Title
Missing Caller Authorization on `reset_timers` Allows Any Principal to Consume the SNS Root Timer Recovery Window - (`rs/sns/root/canister/canister.rs`)

## Summary

The `reset_timers` update method in the SNS Root canister performs no caller identity check, allowing any principal — including anonymous — to invoke it once the 7-day cooldown expires. An attacker can monitor the public `get_timers` query, race to call `reset_timers` at cooldown expiry, and indefinitely block legitimate governance-initiated timer recovery. Every other state-mutating method in the same file is gated on `assert_eq_governance_canister_id`, making this omission a clear inconsistency with the intended access model.

## Finding Description

`reset_timers` is defined at line 487 with the `#[update]` macro and contains exactly one guard — a cooldown check against `last_reset_timestamp_seconds`:

```rust
// rs/sns/root/canister/canister.rs L487-506
#[update]
fn reset_timers(_request: ResetTimersRequest) -> ResetTimersResponse {
    let reset_timers_cool_down_interval_seconds = RESET_TIMERS_COOL_DOWN_INTERVAL.as_secs();
    STATE.with(|state| {
        let state = state.borrow();
        if let Some(timers) = state.timers
            && let Some(last_reset_timestamp_seconds) = timers.last_reset_timestamp_seconds {
                assert!(
                    now_seconds().saturating_sub(last_reset_timestamp_seconds)
                        >= reset_timers_cool_down_interval_seconds, ...
                );
            }
    });
    init_timers();
    ResetTimersResponse {}
}
```

There is no `ic_cdk::api::caller()` check. Every other state-mutating method — `change_canister` (L218), `register_extension` (L257), `clean_up_failed_register_extension` (L292), `register_dapp_canister` (L327), `register_dapp_canisters` (L357), `manage_dapp_canister_settings` (L403) — calls `assert_eq_governance_canister_id(PrincipalId(ic_cdk::api::caller()))` as its first action. `reset_timers` has no equivalent gate.

The cooldown constant is `RESET_TIMERS_COOL_DOWN_INTERVAL = Duration::from_secs(60 * 60 * 24 * 7)` (L49-50). When it expires, the first caller — privileged or not — wins. A successful call invokes `init_timers()` (L466-485), which sets `last_reset_timestamp_seconds` to `now_seconds()` and restarts the interval timer, locking out all callers for another 7 days.

The exploit path:
1. Attacker queries `get_timers` (public query, L459-464) to read `last_reset_timestamp_seconds`.
2. Attacker computes when the cooldown expires and submits an ingress `reset_timers` call at that moment.
3. `init_timers()` executes: `last_reset_timestamp_seconds` is updated to `now`, a new timer is registered, and the old one is cleared.
4. Any subsequent `reset_timers` call — including from governance — panics with the cooldown error for the next 7 days.
5. Attacker repeats every 7 days indefinitely.

## Impact Explanation

The periodic timer drives `run_periodic_tasks` → `SnsRootCanister::poll_for_new_archive_canisters` (L447-457). `reset_timers` is the designated recovery path for when this timer becomes stuck (e.g., after a canister upgrade that clears timer state). By consuming the recovery window every 7 days, an attacker ensures that if the timer fails, legitimate recovery is blocked for up to 7 days per cycle. During that window, archive canister discovery is disrupted: the SNS Root cannot detect new ledger archive canisters, degrading the SNS ledger's historical data management. This constitutes a significant, indefinitely repeatable SNS infrastructure DoS with concrete protocol harm, matching the **High** impact class: *"Application/platform-level DoS... or SNS... security impact with concrete user or protocol harm."*

## Likelihood Explanation

The attack requires no privileged access, no key material, and no social engineering. The SNS Root canister ID is public. `get_timers` is an unauthenticated query. The call is a standard ingress message. The entire attack is fully automatable by a script that polls `get_timers` and fires `reset_timers` at cooldown expiry. It is repeatable indefinitely at zero marginal cost.

## Recommendation

Add a caller authorization check at the top of `reset_timers`, consistent with every other state-mutating method in the file:

```rust
#[update]
fn reset_timers(_request: ResetTimersRequest) -> ResetTimersResponse {
    assert_eq_governance_canister_id(PrincipalId(ic_cdk::api::caller()));
    // ... existing cooldown check ...
    init_timers();
    ResetTimersResponse {}
}
```

If NNS root should also be permitted (as a fallback recovery path), extend `assert_eq_governance_canister_id` or add a secondary check against the NNS root principal.

## Proof of Concept

State-machine / PocketIC test outline:
1. Initialize SNS Root with a known governance canister ID.
2. Advance mock time by `ONE_WEEK_SECONDS` (≥ `RESET_TIMERS_COOL_DOWN_INTERVAL`).
3. Call `reset_timers` as the **anonymous principal** — assert it returns `ResetTimersResponse {}` and `get_timers` shows an updated `last_reset_timestamp_seconds`.
4. Immediately call `reset_timers` again as the anonymous principal — assert it panics with the cooldown message.
5. Call `reset_timers` as the legitimate governance canister — assert it also panics (cooldown consumed by attacker in step 3).
6. Confirm the 7-day window is now locked out for all callers, including governance.

Steps 3–6 are deterministic and require no special infrastructure. The absence of any `caller()` check at lines 487–506 makes step 3 succeed unconditionally for any principal.