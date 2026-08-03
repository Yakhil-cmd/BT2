# Q3855: remote-transfer success drift via encointertreasuries signed payout or on Encointer remote treasury payout hel

## Question
Can an unprivileged attacker enter through `EncointerTreasuries` signed payout or transfer path on Encointer remote treasury payout helper and control beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper so that `TransferOverXcm::get_remote_transfer_xcm` causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid, breaking the invariant that fee assets and transferred assets must reconcile exactly with the remote message that is emitted, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::get_remote_transfer_xcm`
- Entrypoint: `EncointerTreasuries` signed payout or transfer path
- Attacker controls: beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper
- Exploit idea: causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid
- Invariant to test: fee assets and transferred assets must reconcile exactly with the remote message that is emitted
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: integration test that checks local success, remote execution result, and replay resistance together
