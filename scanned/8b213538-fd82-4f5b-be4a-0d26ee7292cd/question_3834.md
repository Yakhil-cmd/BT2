# Q3834: remote-payout beneficiary split via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control asset kinds whose local and remote locations can be reanchored in multiple ways so that `TransferOverXcm::get_remote_transfer_xcm` lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value, breaking the invariant that local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for, and leading to critical - direct loss of funds or duplicated treasury payout?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::get_remote_transfer_xcm`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: asset kinds whose local and remote locations can be reanchored in multiple ways
- Exploit idea: lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value
- Invariant to test: local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for
- Expected Immunefi impact: Critical - direct loss of funds or duplicated treasury payout
- Fast validation: integration test that checks local success, remote execution result, and replay resistance together
