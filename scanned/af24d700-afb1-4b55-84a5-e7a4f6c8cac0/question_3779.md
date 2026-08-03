# Q3779: remote-transfer success drift via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control asset kinds whose local and remote locations can be reanchored in multiple ways so that `fee_asset / ConstantKsmFee` lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value, breaking the invariant that query and response state must not make a remote payout replayable or permanently unclaimable, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `fee_asset / ConstantKsmFee`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: asset kinds whose local and remote locations can be reanchored in multiple ways
- Exploit idea: lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value
- Invariant to test: query and response state must not make a remote payout replayable or permanently unclaimable
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: xcm-emulator test over `get_remote_transfer_xcm`, emitted query state, and final beneficiary accounting
