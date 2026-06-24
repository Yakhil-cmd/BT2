Audit Report

## Title
Wasm Trap in `canister_status` Callback Permanently Leaks `SlotLoan`, Enabling DoS of NNS Root Management Canister Calls — (`rs/nns/handlers/root/impl/canister/canister.rs`)

## Summary

The public `canister_status` update endpoint on the NNS root canister calls `.unwrap()` on the management canister result after the `SlotLoan` RAII guard has already been dropped within the same callback execution. Because the IC rolls back all heap mutations when a response callback traps, the slot restoration performed by `SlotLoan::drop` is undone. An unprivileged caller can exhaust all 167 slots by repeatedly triggering this trap, permanently disabling management canister call capacity for all non-VIP (non-NNS) callers until the canister is upgraded.

## Finding Description

**No access control on entry point:**
`canister_status` at `rs/nns/handlers/root/impl/canister/canister.rs` L88–98 is a bare `#[update]` with no `check_caller_is_*` guard. Any principal may invoke it with an arbitrary `CanisterIdRecord`. [1](#0-0) 

**Slot borrow in Message 1:**
`new_management_canister_client()` wraps the inner client in a `LimitedOutstandingCallsManagementCanisterClient` backed by `AVAILABLE_MANAGEMENT_CANISTER_CALL_SLOT_COUNT` (initialised to 167). When `client.canister_status(...)` is called, `try_borrow_slot` decrements `available_slot_count` and returns a `SlotLoan`. This decrement is committed to the heap before the first `await` suspension point. [2](#0-1) 

**`_loan` scope and drop timing:**
Inside `LimitedOutstandingCallsManagementCanisterClient::canister_status` (L295–301), `_loan` is a local variable whose scope ends when the function returns. In Rust async, the future's state machine (including `_loan`) is dropped as part of completing the `.await` in the caller. Therefore `_loan` is dropped — and `available_slot_count` is incremented — **before** control returns to `canister.rs::canister_status` and before `.unwrap()` is reached. [3](#0-2) 

**`SlotLoan::drop` restores the slot:** [4](#0-3) 

**Trap site — `.unwrap()` after the await:** [5](#0-4) 

**Execution sequence in Message 2 (callback), heap starts at `available_slot_count = N-1`):**
1. `LimitedOutstandingCallsManagementCanisterClient::canister_status` resumes; inner call returns `Err(...)`.
2. `_loan` goes out of scope → `SlotLoan::drop` increments `available_slot_count` to `N`. *(heap mutation)*
3. `Err` propagates back to `canister.rs::canister_status`.
4. `.map(CanisterStatusResult::from)` → still `Err`.
5. `.unwrap()` panics → **Wasm TRAP**.
6. IC rolls back Message 2 heap → `available_slot_count` reverts to `N-1`.

Step 2's increment is permanently undone by step 6. The slot is leaked.

**Exhaustion check — once `available_slot_count == 0`:** [6](#0-5) 

All subsequent non-VIP calls to any `LimitedOutstandingCallsManagementCanisterClient` method immediately return `Err(SysTransient, "Unavailable. Maybe, try again later?")` without making any inter-canister call.

**VIP bypass is irrelevant to the attack:** VIP callers use `used_slot_count = 0` and are unaffected, but the attacker is a non-VIP principal and the victim is the public `canister_status` endpoint (and any other management canister method invoked by non-VIP callers). [7](#0-6) 

## Impact Explanation

After 167 trapped callbacks, every non-VIP call to any management canister method routed through `LimitedOutstandingCallsManagementCanisterClient` on the NNS root canister returns a `SysTransient` error immediately. The public `canister_status` endpoint becomes permanently non-functional for all non-NNS principals until the canister is upgraded or restarted. This constitutes an **application/platform-level DoS** of an NNS governance infrastructure canister, matching the **High ($2,000–$10,000)** impact class: "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."

## Likelihood Explanation

- The `canister_status` endpoint is public with no access control; any principal can call it.
- Triggering a management canister rejection is trivial: pass any canister ID that NNS root does not control (e.g., any user-owned canister). The management canister rejects `canister_status` calls from non-controllers.
- Only 167 update calls are required. Each costs only standard ingress fees.
- No privileged access, key material, subnet-majority corruption, or social engineering is required.
- The attack is fully deterministic and repeatable.

## Recommendation

Replace `.unwrap()` with proper error propagation so the endpoint returns a rejection to the caller instead of trapping:

```rust
// canister.rs L97 — instead of:
canister_status_response.unwrap()

// Use (CDK trap encodes a reject, no heap rollback):
canister_status_response.map_err(|(_, msg)| ic_cdk::trap(&msg))
// or change the return type to Result<CanisterStatusResult, ...> and propagate
```

This ensures that when the management canister returns an error, the canister replies with a rejection rather than trapping, so no heap rollback occurs and `SlotLoan::drop`'s increment is preserved.

## Proof of Concept

1. Obtain any canister ID that NNS root does not control (e.g., a freshly created user canister on mainnet or a local replica).
2. Send 167 update calls to NNS root's `canister_status` endpoint with that canister ID.
3. Each call: management canister rejects (NNS root is not a controller) → `Err` returned → `_loan` dropped (slot restored in heap) → `.unwrap()` traps → IC rolls back callback heap → slot leaked.
4. On the 168th call from any non-VIP principal to any management canister method, observe `Err(SysTransient, "Unavailable. Maybe, try again later?")` returned immediately without any inter-canister call being made.
5. Confirm with a PocketIC integration test: set up NNS root, call `canister_status` 167 times with a non-controlled canister ID, then assert the 168th call returns the `SysTransient` error.

### Citations

**File:** rs/nns/handlers/root/impl/canister/canister.rs (L88-98)
```rust
#[update]
async fn canister_status(canister_id_record: CanisterIdRecord) -> CanisterStatusResult {
    let client = new_management_canister_client();

    let canister_status_response = client
        .canister_status(canister_id_record)
        .await
        .map(CanisterStatusResult::from);

    canister_status_response.unwrap()
}
```

**File:** rs/nervous_system/clients/src/management_canister_client.rs (L264-287)
```rust
    fn try_borrow_slot(&self) -> Result<SlotLoan, (i32, String)> {
        let used_slot_count = if self.is_caller_vip { 0 } else { 1 };

        self.available_slot_count
            .with_borrow_mut(|available_slot_count| {
                if *available_slot_count == 0 {
                    // This is somewhat of a lie, but is the best fit.
                    let code = RejectCode::SysTransient as i32;

                    let message = "Unavailable. Maybe, try again later?".to_string();

                    return Err((code, message));
                }

                *available_slot_count = available_slot_count.saturating_sub(used_slot_count);
                Ok(())
            })?;

        let available_slot_count = self.available_slot_count;
        Ok(SlotLoan {
            available_slot_count,
            used_slot_count,
        })
    }
```

**File:** rs/nervous_system/clients/src/management_canister_client.rs (L295-301)
```rust
    async fn canister_status(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<CanisterStatusResultFromManagementCanister, (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.canister_status(canister_id_record).await
    }
```

**File:** rs/nervous_system/clients/src/management_canister_client.rs (L365-372)
```rust
impl Drop for SlotLoan {
    fn drop(&mut self) {
        self.available_slot_count
            .with_borrow_mut(|available_slot_count| {
                *available_slot_count = available_slot_count.saturating_add(self.used_slot_count);
            });
    }
}
```
