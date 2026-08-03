# Q3786: remote-payout beneficiary split via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper so that `fee_asset / ConstantKsmFee` lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value, breaking the invariant that fee assets and transferred assets must reconcile exactly with the remote message that is emitted, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `fee_asset / ConstantKsmFee`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper
- Exploit idea: lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value
- Invariant to test: fee assets and transferred assets must reconcile exactly with the remote message that is emitted
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: integration test that checks local success, remote execution result, and replay resistance together
