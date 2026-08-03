# Q3804: fee-asset settlement mismatch via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control batched treasury payouts that reuse the same source account and remote execution fee assumptions so that `TransferOverXcm::from_on_remote` causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid, breaking the invariant that fee assets and transferred assets must reconcile exactly with the remote message that is emitted, and leading to critical - direct loss of funds or duplicated treasury payout?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::from_on_remote`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: batched treasury payouts that reuse the same source account and remote execution fee assumptions
- Exploit idea: causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid
- Invariant to test: fee assets and transferred assets must reconcile exactly with the remote message that is emitted
- Expected Immunefi impact: Critical - direct loss of funds or duplicated treasury payout
- Fast validation: xcm-emulator test over `get_remote_transfer_xcm`, emitted query state, and final beneficiary accounting
