# Q3806: remote-payout beneficiary split via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control asset kinds whose local and remote locations can be reanchored in multiple ways so that `TransferOverXcm::from_on_remote` makes fee charging and remote settlement use different asset identities or amounts, breaking the invariant that one treasury payout must map to one remote transfer and one final beneficiary, and leading to high - stuck remote payout queue with concrete fund impact?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::from_on_remote`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: asset kinds whose local and remote locations can be reanchored in multiple ways
- Exploit idea: makes fee charging and remote settlement use different asset identities or amounts
- Invariant to test: one treasury payout must map to one remote transfer and one final beneficiary
- Expected Immunefi impact: High - stuck remote payout queue with concrete fund impact
- Fast validation: xcm-emulator test over `get_remote_transfer_xcm`, emitted query state, and final beneficiary accounting
