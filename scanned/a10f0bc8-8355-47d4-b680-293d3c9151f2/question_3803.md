# Q3803: remote-transfer success drift via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control batched treasury payouts that reuse the same source account and remote execution fee assumptions so that `TransferOverXcm::from_on_remote` lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value, breaking the invariant that fee assets and transferred assets must reconcile exactly with the remote message that is emitted, and leading to high - stuck remote payout queue with concrete fund impact?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::from_on_remote`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: batched treasury payouts that reuse the same source account and remote execution fee assumptions
- Exploit idea: lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value
- Invariant to test: fee assets and transferred assets must reconcile exactly with the remote message that is emitted
- Expected Immunefi impact: High - stuck remote payout queue with concrete fund impact
- Fast validation: xcm-emulator test over `get_remote_transfer_xcm`, emitted query state, and final beneficiary accounting
