# Q3805: query-state replay on payout via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control asset kinds whose local and remote locations can be reanchored in multiple ways so that `TransferOverXcm::from_on_remote` reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once, breaking the invariant that local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::from_on_remote`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: asset kinds whose local and remote locations can be reanchored in multiple ways
- Exploit idea: reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once
- Invariant to test: local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: xcm-emulator test over `get_remote_transfer_xcm`, emitted query state, and final beneficiary accounting
