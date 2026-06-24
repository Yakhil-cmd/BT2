The code is confirmed. Both files match the claim exactly. The bug is real.

Audit Report

## Title
VIP Caller Starvation via Slot Exhaustion in `try_borrow_slot` — (`rs/nervous_system/clients/src/management_canister_client.rs`)

## Summary
`LimitedOutstandingCallsManagementCanisterClient::try_borrow_slot` unconditionally rejects callers when `available_slot_count == 0`, including VIP callers (NNS canisters) whose `used_slot_count` is 0 and would not consume a slot. An unprivileged external principal can exhaust all 167 slots via the unauthenticated `canister_status` endpoint on NNS Root, causing NNS Governance's calls to Root to trap, blocking governance-critical canister-status queries for the duration of the attack.

## Finding Description
In `rs/nervous_system/clients/src/management_canister_client.rs` at L264–287, `try_borrow_slot` computes `used_slot_count = 0` for VIP callers but then evaluates the exhaustion guard `if *available_slot_count == 0` unconditionally before that distinction is applied:

```rust
fn try_borrow_slot(&self) -> Result<SlotLoan, (i32, String)> {
    let used_slot_count = if self.is_caller_vip { 0 } else { 1 };  // VIP = 0 slots

    self.available_slot_count
        .with_borrow_mut(|available_slot_count| {
            if *available_slot_count == 0 {          // fires for VIP too — BUG
                return Err((RejectCode::SysTransient as i32, "Unavailable...".to_string()));
            }
            *available_slot_count = available_slot_count.saturating_sub(used_slot_count);
            Ok(())
        })?;
```

The exploit path:
1. `AVAILABLE_MANAGEMENT_CANISTER_CALL_SLOT_COUNT` is initialized to 167 (`rs/nns/handlers/root/impl/canister/canister.rs` L50).
2. The `canister_status` update endpoint on NNS Root (L88–98) has no authentication check — any external principal can call it.
3. Each non-VIP call to `canister_status` creates a client with `is_caller_vip = false` (L58–60), borrows one slot, and holds the `SlotLoan` for the entire management canister round-trip.
4. With 167 concurrent in-flight calls from unprivileged principals, `available_slot_count` reaches 0.
5. When NNS Governance (a VIP, present in `ALL_NNS_CANISTER_IDS`) subsequently calls Root's `canister_status`, `new_management_canister_client()` sets `is_caller_vip = true`, but `try_borrow_slot` still hits the `== 0` guard and returns `Err(SysTransient, "Unavailable...")`.
6. Root's handler calls `canister_status_response.unwrap()` (L97), which traps, causing Governance's inter-canister call to Root to receive a reject response.

Existing guards are insufficient: the `is_caller_vip` flag is set correctly but is never consulted before the exhaustion check fires.

## Impact Explanation
This is an application/platform-level DoS against NNS governance operations, not based on raw volumetric DDoS. NNS Governance's canister-status-dependent flows (e.g., SNS-W's `get_controllers_of_nns_root_owned_canister`, upgrade proposal validation) fail transiently for the duration of the attack. The attack is triggered by an unprivileged external user exploiting a logic flaw in a production NNS canister. This matches the **High ($2,000–$10,000)** impact class: "Application/platform-level DoS… not based on raw volumetric DDoS" with concrete NNS governance harm.

## Likelihood Explanation
Maintaining 167 concurrent in-flight update calls to NNS Root requires no privileged access, no coordination, and no special protocol knowledge. Each call awaits a management canister response (a few consensus rounds), so the attacker must continuously submit new calls as old ones complete — feasible from a single principal. The IC ingress queue limit (~500 messages) is not a binding constraint at 167 concurrent calls. The attack is repeatable and cheap.

## Recommendation
In `try_borrow_slot`, condition the exhaustion guard on `!self.is_caller_vip`:

```rust
fn try_borrow_slot(&self) -> Result<SlotLoan, (i32, String)> {
    let used_slot_count = if self.is_caller_vip { 0 } else { 1 };

    self.available_slot_count
        .with_borrow_mut(|available_slot_count| {
            if !self.is_caller_vip && *available_slot_count == 0 {
                let code = RejectCode::SysTransient as i32;
                return Err((code, "Unavailable. Maybe, try again later?".to_string()));
            }
            *available_slot_count = available_slot_count.saturating_sub(used_slot_count);
            Ok(())
        })?;
    ...
}
```

This preserves the invariant that VIP callers are never rejected by the slot guard regardless of non-VIP slot occupancy.

## Proof of Concept
Extend the existing test infrastructure in `rs/nervous_system/clients/src/management_canister_client/tests.rs`:

1. Initialize `LimitedOutstandingCallsManagementCanisterClient` with `available_slot_count = 167`.
2. Spawn 167 concurrent non-VIP `canister_status` calls using a mock inner client that never resolves (holds `SlotLoan` indefinitely).
3. Assert `available_slot_count == 0`.
4. Issue one VIP (`is_caller_vip = true`) `canister_status` call.
5. Observe: returns `Err(SysTransient, "Unavailable. Maybe, try again later?")` — confirms the bug.
6. Apply the fix (guard conditioned on `!is_caller_vip`).
7. Repeat step 4 — call now succeeds, confirming the fix.