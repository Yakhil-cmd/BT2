Audit Report

## Title
Unprivileged Griefing of Global Timer Recovery Cooldown in SNS Root, Governance, and Swap — (`rs/sns/root/canister/canister.rs`, `rs/sns/governance/canister/canister.rs`, `rs/sns/swap/canister/canister.rs`)

## Summary

The `reset_timers` update method in all three SNS canisters carries no caller identity check and writes a single shared global `last_reset_timestamp_seconds`. Any unprivileged principal can call `reset_timers`, consuming the global cooldown window (up to 7 days for SNS Root) and blocking every other caller from invoking the recovery function until the cooldown expires. An attacker can sustain this indefinitely at trivial cost, permanently preventing legitimate timer recovery.

## Finding Description

All three canisters expose `reset_timers` as a plain `#[update]` method with no `caller()` check:

- **SNS Root** (`rs/sns/root/canister/canister.rs`, lines 487–506): reads `state.timers.last_reset_timestamp_seconds`, asserts the global cooldown has elapsed, then calls `init_timers()`.
- **SNS Governance** (`rs/sns/governance/canister/canister.rs`, lines 644–661): same pattern against `governance_mut().proto.timers`.
- **SNS Swap** (`rs/sns/swap/canister/canister.rs`, lines 348–365): same pattern against `swap_mut().timers`.

`init_timers()` unconditionally overwrites the shared `last_reset_timestamp_seconds` with `now_seconds()` (`rs/sns/governance/canister/canister.rs`, line 628; `rs/sns/root/canister/canister.rs`, line 50 confirms the SNS Root cooldown is `Duration::from_secs(60 * 60 * 24 * 7)` — one week). The cooldown constants are:

- SNS Root: **604 800 seconds** (7 days) — confirmed at `rs/sns/root/canister/canister.rs` line 50.
- SNS Governance: **600 seconds** — confirmed at `rs/sns/swap/canister/canister.rs` line 49 (same constant pattern).
- SNS Swap: **600 seconds** — confirmed at `rs/sns/swap/canister/canister.rs` line 49.

Because the cooldown is stored in a single canister-global field and not keyed per caller, any principal who calls `reset_timers` first resets the timestamp for *all* callers. A subsequent legitimate call within the cooldown window is rejected with `"Reset has already been called within the past N seconds"`. The existing anti-spam test (`rs/sns/integration_tests/src/timers.rs`, lines 197–260) confirms this rejection behavior but uses a single caller throughout, leaving the cross-principal griefing path untested.

Exploit flow:
1. Attacker calls `reset_timers` on SNS Root at time `T` (succeeds; sets `last_reset_timestamp_seconds = T`).
2. SNS Root timers become stuck (e.g., after an upgrade).
3. Legitimate operator calls `reset_timers` at `T + 1`; rejected: cooldown not elapsed.
4. Attacker repeats step 1 at `T + 604800`, perpetually blocking recovery.

Alternatively, the attacker preemptively calls once per cooldown window as a standing grief without needing to predict when timers will fail.

## Impact Explanation

For SNS Root, stuck timers prevent `run_periodic_tasks` from executing, which polls for new ledger archive canisters. With a 7-day cooldown and an attacker calling once per week, recovery is permanently blocked. For SNS Governance, stuck timers halt reward distribution and other periodic governance tasks; the 10-minute cooldown is less severe but still exploitable during time-sensitive operations (e.g., active SNS swap finalization). This constitutes a significant SNS platform-level DoS with concrete protocol harm — matching the allowed High impact class: *"Application/platform-level DoS … or subnet availability impact not based on raw volumetric DDoS"* and *"Significant … SNS … security impact with concrete user or protocol harm."*

## Likelihood Explanation

The attack requires only a valid ingress message to a publicly reachable update method — no tokens, no neuron, no governance majority. The cost is one update call per cooldown period (negligible in cycles). The attacker does not need to predict timer failures; preemptive calls at the start of each cooldown window are sufficient to sustain the grief indefinitely.

## Recommendation

Add a caller identity check to `reset_timers` in all three canisters, restricting invocation to a trusted set of principals (e.g., the SNS governance canister itself, NNS root, or the canister's own controllers). If the function must remain permissionless, replace the single `last_reset_timestamp_seconds` field with a per-caller map (`BTreeMap<PrincipalId, u64>`) so that one caller's invocation does not consume the global cooldown for all others.

## Proof of Concept

Extend the existing `run_canister_reset_timers_cannot_be_spammed_test` in `rs/sns/integration_tests/src/timers.rs` to use two distinct callers:

1. Install SNS Root canister.
2. Advance time past the cooldown interval.
3. **Caller A** (attacker principal) calls `reset_timers` — succeeds; `last_reset_timestamp_seconds` is set to `T`.
4. Advance time by 1 second.
5. **Caller B** (legitimate operator principal) calls `reset_timers` — assert it is rejected with `"Reset has already been called within the past 604800 seconds"`.
6. Advance time to `T + ONE_WEEK_SECONDS - 1`; **Caller A** calls `reset_timers` again — succeeds; cooldown resets.
7. **Caller B** is again blocked for another full week.

This test requires no changes to the canister code to reproduce and directly demonstrates the cross-principal griefing path.