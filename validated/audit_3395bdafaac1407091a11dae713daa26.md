Audit Report

## Title
VIP Caller Bypass Broken in `try_borrow_slot`: Non-VIP Slot Exhaustion Blocks NNS Canister Management Operations — (File: `rs/nervous_system/clients/src/management_canister_client.rs`)

## Summary

In `LimitedOutstandingCallsManagementCanisterClient::try_borrow_slot`, the `available_slot_count == 0` guard at line 269 fires unconditionally for all callers before the VIP-specific `used_slot_count = 0` path at line 265 can take effect. An unprivileged user can exhaust all 167 slots via the public `canister_status` endpoint on the NNS root canister, causing VIP callers (NNS governance and other NNS canisters) to receive `SysTransient` errors on subsequent management canister operations routed through root, blocking NNS canister upgrade and management proposals.

## Finding Description

In `try_borrow_slot` (`rs/nervous_system/clients/src/management_canister_client.rs`, lines 264–287):

```rust
fn try_borrow_slot(&self) -> Result<SlotLoan, (i32, String)> {
    let used_slot_count = if self.is_caller_vip { 0 } else { 1 };

    self.available_slot_count
        .with_borrow_mut(|available_slot_count| {
            if *available_slot_count == 0 {   // ← no is_caller_vip check
                let code = RejectCode::SysTransient as i32;
                let message = "Unavailable. Maybe, try again later?".to_string();
                return Err((code, message));
            }
            *available_slot_count = available_slot_count.saturating_sub(used_slot_count);
            Ok(())
        })?;
    ...
}
``` [1](#0-0) 

The intent is that VIP callers (`is_caller_vip = true`) consume zero slots (`used_slot_count = 0`) and are never rate-limited. However, the `== 0` guard is evaluated **before** the subtraction and does not check `is_caller_vip`. When `available_slot_count` reaches zero, the guard returns `Err` for every caller regardless of VIP status.

The slot pool is initialized to 167 in the NNS root canister: [2](#0-1) 

The `canister_status` endpoint is explicitly public (no access control), and `new_management_canister_client()` derives `is_caller_vip` from the caller at request time: [3](#0-2) [4](#0-3) 

An attacker submits 167 concurrent update calls to the public `canister_status` endpoint. Each call suspends at the `await management_canister.canister_status()` point (IC async model: canister processes next message while awaiting inter-canister response), holding one slot. Once `available_slot_count == 0`, any subsequent call — including from NNS governance — hits the guard and receives `SysTransient`. The `SlotLoan` drop implementation adds back `used_slot_count` (which is 0 for VIP), so even if a VIP call somehow succeeded, it would not restore slots: [5](#0-4) 

All management canister operations route through `try_borrow_slot`, including `stop_canister`, `update_settings`, `delete_canister`, `take_canister_snapshot`, and `load_canister_snapshot`: [6](#0-5) 

## Impact Explanation

This is a **High** severity application/platform-level DoS. When slots are exhausted, NNS governance's calls to `change_nns_canister` (which internally calls `stop_canister`, `update_settings`, etc. through root) fail with `SysTransient`. This blocks execution of NNS canister upgrade proposals and other NNS canister management operations for the duration of the attack. The `change_nns_canister` endpoint enforces `check_caller_is_governance()` but relies on `new_management_canister_client()` setting `is_caller_vip = true` for governance — a protection that the bug renders ineffective. [7](#0-6) 

## Likelihood Explanation

- The `canister_status` endpoint has no access control and is documented as intentionally public.
- 167 concurrent in-flight calls is well within the IC message queue limit of 500.
- The attack is deterministic: slot exhaustion is a simple counter reaching zero.
- No privileged access, key material, or consensus corruption is required.
- The attacker must maintain a steady stream of calls (management canister calls complete in seconds), but this is feasible via repeated ingress submissions from an anonymous principal.

## Recommendation

Add a VIP bypass to the `== 0` guard in `try_borrow_slot`:

```rust
if !self.is_caller_vip && *available_slot_count == 0 {
    let code = RejectCode::SysTransient as i32;
    let message = "Unavailable. Maybe, try again later?".to_string();
    return Err((code, message));
}
```

This ensures VIP callers always proceed regardless of slot exhaustion, matching the documented intent ("VIP = is an NNS canister"). [8](#0-7) 

## Proof of Concept

Using the existing test infrastructure in `rs/nns/handlers/root/impl/tests/test.rs` with `state_machine_test_on_nns_subnet` and `update_with_sender`:

1. Install the NNS root canister with `AVAILABLE_MANAGEMENT_CANISTER_CALL_SLOT_COUNT = 167`.
2. Install a slow-responding canister (e.g., universal canister configured to delay its management canister response).
3. Submit 167 concurrent non-VIP `canister_status` update calls (from anonymous principal) targeting the slow canister to hold all slots open.
4. Assert `available_slot_count == 0`.
5. Submit a `canister_status` or `change_nns_canister` call from an NNS canister principal (`is_caller_vip = true`).
6. Assert the response is `Err((SysTransient, "Unavailable. Maybe, try again later?"))` — demonstrating VIP is blocked despite `used_slot_count = 0`.

### Citations

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

**File:** rs/nervous_system/clients/src/management_canister_client.rs (L326-356)
```rust
    async fn stop_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.stop_canister(canister_id_record).await
    }

    async fn delete_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.delete_canister(canister_id_record).await
    }

    async fn take_canister_snapshot(
        &self,
        args: TakeCanisterSnapshotArgs,
    ) -> Result<CanisterSnapshotResponse, (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.take_canister_snapshot(args).await
    }

    async fn load_canister_snapshot(
        &self,
        args: LoadCanisterSnapshotArgs,
    ) -> Result<(), (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.load_canister_snapshot(args).await
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

**File:** rs/nns/handlers/root/impl/canister/canister.rs (L47-51)
```rust
thread_local! {
    // How this value was chosen: queues become full at 500. This is 1/3 of that, which seems to be
    // a reasonable balance.
    static AVAILABLE_MANAGEMENT_CANISTER_CALL_SLOT_COUNT: RefCell<u64> = const { RefCell::new(167) };
}
```

**File:** rs/nns/handlers/root/impl/canister/canister.rs (L53-67)
```rust
fn new_management_canister_client() -> impl ManagementCanisterClient {
    let client =
        ManagementCanisterClientImpl::<CdkRuntime>::new(Some(&PROXIED_CANISTER_CALLS_TRACKER));

    // Here, VIP = is an NNS canister
    let is_caller_vip = CanisterId::try_from(caller())
        .map(|caller| ALL_NNS_CANISTER_IDS.contains(&&caller))
        .unwrap_or(false);

    LimitedOutstandingCallsManagementCanisterClient::new(
        client,
        &AVAILABLE_MANAGEMENT_CANISTER_CALL_SLOT_COUNT,
        is_caller_vip,
    )
}
```

**File:** rs/nns/handlers/root/impl/canister/canister.rs (L81-98)
```rust
/// Returns the status of the canister specified in the input.
///
/// The status of NNS canisters should be public information: anyone can get the
/// status of any NNS canister.
///
/// This must be an update, not a query, because an inter-canister call to the
/// management canister is required.
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

**File:** rs/nns/handlers/root/impl/canister/canister.rs (L134-165)
```rust
/// Executes a proposal to change an NNS canister.
#[update]
fn change_nns_canister(request: ChangeCanisterRequest) {
    check_caller_is_governance();
    // We want to reply first, so that in the case that we want to upgrade the
    // governance canister, the root canister no longer holds a pending callback
    // to it -- and therefore does not prevent the governance canister from being
    // stopped.
    //
    // To do so, we use `over` instead of the more common `over_async`.
    //
    // This will effectively reply synchronously with the first call to the
    // management canister in change_canister.

    // Because change_canister is async, and because we can't directly use
    // `await`, we need to use the `spawn` trick.
    let future = async move {
        let change_canister_result = change_canister(request).await;
        match change_canister_result {
            Ok(()) => {
                println!("{LOG_PREFIX}change_canister: Canister change completed successfully.");
            }
            Err(err) => {
                println!("{LOG_PREFIX}change_canister: Canister change failed: {err}");
            }
        };
    };

    // Starts the proposal execution, which will continue after this function has
    // returned.
    spawn_017_compat(future);
}
```
