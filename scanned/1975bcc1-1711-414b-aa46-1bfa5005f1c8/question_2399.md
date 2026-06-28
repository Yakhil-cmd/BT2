# Q2399: connector ft and storage methods silo bypass through connector target account selection in `return_promise`

## Question
Can an attacker use `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract so that connector target account selection in `return_promise` reaches token receive, submit, deploy, or mirror behavior that silo mode was supposed to block, resulting in Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_transfer / ft_transfer_call / storage_* / return_promise` -> `connector target account selection in `return_promise``
- Entrypoint: `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract
- Attacker controls: JSON transfer and storage arguments, attached deposit, attached 1 yocto where required, target account IDs, and repeated request ordering
- Exploit idea: find a public path around the targeted silo-related check.
- Invariant to test: proxy methods into the NEAR-side connector must preserve exactly one intended account, amount, memo/message, and attached-balance meaning
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Enable silo restrictions in state and verify every alternate public path still rejects the same blocked action. write integration tests that inspect generated promise payloads and balances for transfer and storage calls under crafted JSON arguments and deposit values
