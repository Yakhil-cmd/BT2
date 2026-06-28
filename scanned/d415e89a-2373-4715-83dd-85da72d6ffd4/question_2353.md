# Q2353: connector ft and storage methods rollback gap after one-yocto checks on transfer and storage exits

## Question
Can an attacker make one-yocto checks on transfer and storage exits mutate state or emit a promise before a later failing step aborts the public call, leaving a rollback gap that can be exploited for Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_transfer / ft_transfer_call / storage_* / return_promise` -> `one-yocto checks on transfer and storage exits`
- Entrypoint: `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract
- Attacker controls: JSON transfer and storage arguments, attached deposit, attached 1 yocto where required, target account IDs, and repeated request ordering
- Exploit idea: force a failure immediately after the named connector mutation or promise creation.
- Invariant to test: proxy methods into the NEAR-side connector must preserve exactly one intended account, amount, memo/message, and attached-balance meaning
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Cause the downstream step to fail and verify all earlier state, supply, and mapping changes are either rolled back or safely compensated. write integration tests that inspect generated promise payloads and balances for transfer and storage calls under crafted JSON arguments and deposit values
