# Q3807: remote-transfer success drift via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control asset kinds whose local and remote locations can be reanchored in multiple ways so that `TransferOverXcm::from_on_remote` causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid, breaking the invariant that query and response state must not make a remote payout replayable or permanently unclaimable, and leading to high - stuck remote payout queue with concrete fund impact?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::from_on_remote`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: asset kinds whose local and remote locations can be reanchored in multiple ways
- Exploit idea: causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid
- Invariant to test: query and response state must not make a remote payout replayable or permanently unclaimable
- Expected Immunefi impact: High - stuck remote payout queue with concrete fund impact
- Fast validation: integration test that checks local success, remote execution result, and replay resistance together
