# Q3858: remote-payout beneficiary split via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control batched treasury payouts that reuse the same source account and remote execution fee assumptions so that `TransferOverXcm::transfer` lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value, breaking the invariant that one treasury payout must map to one remote transfer and one final beneficiary, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::transfer`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: batched treasury payouts that reuse the same source account and remote execution fee assumptions
- Exploit idea: lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value
- Invariant to test: one treasury payout must map to one remote transfer and one final beneficiary
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: integration test that checks local success, remote execution result, and replay resistance together
