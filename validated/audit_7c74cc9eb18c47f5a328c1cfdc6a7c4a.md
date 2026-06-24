Audit Report

## Title
TOCTOU Race: Original Dapp Controller Can Install Malicious Wasm During SNS Registration Window — (File: `rs/sns/root/src/lib.rs`)

## Summary

`SnsRootCanister::register_dapp_canister` performs a `canister_status` inter-canister call to verify SNS Root is a controller, then a separate `update_settings` inter-canister call to evict all other controllers. Between these two async await points, the IC message scheduler can process ingress messages from other principals. The original dapp controller — still listed as a controller after the first await — can submit an `install_code` ingress to `ic:00` targeting the dapp canister, replacing its Wasm before the controller eviction completes. The post-eviction sanity check only verifies the controller list, not the module hash, so registration succeeds with attacker-controlled code installed.

## Finding Description

In `rs/sns/root/src/lib.rs`, `register_dapp_canister` (lines 662–746) executes the following sequence:

1. **First await** (line 703–706): `canister_status` is called. SNS Root suspends and yields to the IC scheduler.
2. **Controller check** (lines 708–711): confirms SNS Root is in the controller list.
3. **Second await** (lines 718–728): `update_settings` is called with `controllers: Some(vec![root_canister_id])`. SNS Root suspends again.
4. **Third await** (lines 732–735): a second `canister_status` is called as a sanity check.
5. **Sanity check** (line 736): verifies `controllers == vec![root_canister_id]`. **No module hash check is performed.**

Between step 1 and step 3, the IC scheduler is free to process other messages. The original dapp controller D, who is still a controller of canister C at the time of step 1, can submit an ingress `install_code` call to `ic:00` targeting C. The IC execution environment's `can_execute_subnet_msg` guard (scheduler.rs lines 1829–1882) only blocks subnet messages targeting a canister that has a `PausedExecution` or `PausedInstallCode` in its own task queue. Canister C has no such paused execution — it is SNS Root that is suspended. Therefore D's `install_code` is not blocked and executes successfully, replacing C's Wasm module. When SNS Root's continuation resumes and calls `update_settings`, D is evicted as a controller, but the malicious Wasm is already installed. The final sanity check at line 736 only checks `controllers()`, not `module_hash()`, so registration completes successfully with the tampered canister.

## Impact Explanation

SNS participants who voted to acquire the dapp receive governance over a canister whose Wasm module has been replaced by the original controller. Depending on the dapp's function, the malicious Wasm can drain user funds, install backdoors, or destroy protocol state. This constitutes a **High** impact: "Significant SNS security impact with concrete user or protocol harm." The original controller receives ICP/SNS tokens from the swap while having degraded or backdoored the asset being transferred.

## Likelihood Explanation

The attacker is the original dapp controller — a party with a direct financial incentive (receiving swap proceeds) and the exact capability needed (controller rights over C during the window). The exploit window spans one inter-canister call round-trip (~2 seconds on mainnet), which is sufficient for an ingress `install_code` message to be inducted and executed in a subsequent consensus round. No governance majority, subnet corruption, leaked key, or social engineering is required. The attack is repeatable for every SNS launch where the original controller is adversarial.

## Recommendation

1. **Check module hash after eviction**: After `update_settings` completes, call `canister_status` again and compare `module_hash` against the hash recorded at SNS proposal submission time. Reject registration if the hash differs.
2. **Snapshot module hash at proposal time**: Record the dapp canister's Wasm module hash in the SNS init payload or governance proposal and enforce it at registration time.
3. **Interim documentation**: Until a technical fix is deployed, communicate to SNS launch participants that the original dapp controller retains the ability to modify the dapp between the governance proposal passing and the controller transfer completing.

## Proof of Concept

Using PocketIC's `submit_call` / `await_call` concurrent execution API (documented in `packages/pocket-ic/HOWTO.md`, lines 134–191):

```
1. Deploy SNS Root (R), dapp canister C with controller D.
2. D calls update_settings on ic:00 to add R as co-controller of C.
3. SNS Governance calls register_dapp_canister(C) on R.
   - R issues canister_status(C) [first await — R is now suspended].
4. Using submit_call (without await), submit from D:
     install_code { canister_id: C, wasm_module: <malicious_wasm>, mode: Reinstall }
   to ic:00.
5. Advance the IC by one tick (pic.tick()) so D's install_code executes
   while R's continuation is still queued.
6. Allow R's continuation to resume: update_settings removes D,
   second canister_status confirms controllers == [R].
7. Registration returns Ok(()).
8. Assert canister_status(C).module_hash == hash(<malicious_wasm>).
   // Confirms malicious Wasm is installed despite successful registration.
```

The deterministic PocketIC tick-level control makes this race condition fully reproducible in a local integration test without any mainnet interaction.