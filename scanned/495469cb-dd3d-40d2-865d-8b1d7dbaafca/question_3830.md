# Q3830: remote-payout beneficiary split via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control batched treasury payouts that reuse the same source account and remote execution fee assumptions so that `TransferOverXcm::get_remote_transfer_xcm` makes fee charging and remote settlement use different asset identities or amounts, breaking the invariant that one treasury payout must map to one remote transfer and one final beneficiary, and leading to critical - direct loss of funds or duplicated treasury payout?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::get_remote_transfer_xcm`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: batched treasury payouts that reuse the same source account and remote execution fee assumptions
- Exploit idea: makes fee charging and remote settlement use different asset identities or amounts
- Invariant to test: one treasury payout must map to one remote transfer and one final beneficiary
- Expected Immunefi impact: Critical - direct loss of funds or duplicated treasury payout
- Fast validation: xcm-emulator test over `get_remote_transfer_xcm`, emitted query state, and final beneficiary accounting
