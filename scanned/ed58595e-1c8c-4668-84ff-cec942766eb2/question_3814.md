# Q3814: remote-payout beneficiary split via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper so that `TransferOverXcm::from_on_remote` causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid, breaking the invariant that query and response state must not make a remote payout replayable or permanently unclaimable, and leading to critical - direct loss of funds or duplicated treasury payout?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::from_on_remote`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper
- Exploit idea: causes the local payout logic and remote-transfer XCM to disagree about which beneficiary or asset is actually being paid
- Invariant to test: query and response state must not make a remote payout replayable or permanently unclaimable
- Expected Immunefi impact: Critical - direct loss of funds or duplicated treasury payout
- Fast validation: stateful fuzz test over asset location, beneficiary conversion, and payment-status replay
