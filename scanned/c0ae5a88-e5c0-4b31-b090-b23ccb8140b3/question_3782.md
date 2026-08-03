# Q3782: remote-payout beneficiary split via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control query ids, timeout windows, and replayed payment-status checks around the same remote transfer so that `fee_asset / ConstantKsmFee` makes fee charging and remote settlement use different asset identities or amounts, breaking the invariant that local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `fee_asset / ConstantKsmFee`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: query ids, timeout windows, and replayed payment-status checks around the same remote transfer
- Exploit idea: makes fee charging and remote settlement use different asset identities or amounts
- Invariant to test: local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: xcm-emulator test over `get_remote_transfer_xcm`, emitted query state, and final beneficiary accounting
