# Q3835: remote-transfer success drift via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control asset kinds whose local and remote locations can be reanchored in multiple ways so that `TransferOverXcm::get_remote_transfer_xcm` causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid, breaking the invariant that one treasury payout must map to one remote transfer and one final beneficiary, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::get_remote_transfer_xcm`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: asset kinds whose local and remote locations can be reanchored in multiple ways
- Exploit idea: causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid
- Invariant to test: one treasury payout must map to one remote transfer and one final beneficiary
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: stateful fuzz test over asset location, beneficiary conversion, and payment-status replay
