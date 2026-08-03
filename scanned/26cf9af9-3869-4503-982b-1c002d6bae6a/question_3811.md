# Q3811: remote-transfer success drift via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control query ids, timeout windows, and replayed payment-status checks around the same remote transfer so that `TransferOverXcm::from_on_remote` causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid, breaking the invariant that local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for, and leading to critical - direct loss of funds or duplicated treasury payout?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::from_on_remote`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: query ids, timeout windows, and replayed payment-status checks around the same remote transfer
- Exploit idea: causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid
- Invariant to test: local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for
- Expected Immunefi impact: Critical - direct loss of funds or duplicated treasury payout
- Fast validation: stateful fuzz test over asset location, beneficiary conversion, and payment-status replay
