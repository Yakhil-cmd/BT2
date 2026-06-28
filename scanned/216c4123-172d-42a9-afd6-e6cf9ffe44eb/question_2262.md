# Q2262: connector ft and storage methods double-apply path at JSON parsing of `FtTransferCallArgs`

## Question
Can an attacker trigger JSON parsing of `FtTransferCallArgs` twice for one logical action through retries, repeated calls, or callback reuse from `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract, so burn, mint, refund, or registration state is applied more than once and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_transfer / ft_transfer_call / storage_* / return_promise` -> `JSON parsing of `FtTransferCallArgs``
- Entrypoint: `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract
- Attacker controls: JSON transfer and storage arguments, attached deposit, attached 1 yocto where required, target account IDs, and repeated request ordering
- Exploit idea: look for a one-to-many application of one user action around the targeted connector step.
- Invariant to test: proxy methods into the NEAR-side connector must preserve exactly one intended account, amount, memo/message, and attached-balance meaning
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Replay the same logical action across repeated calls and callback timing variations and assert supply, mappings, and balances remain single-applied. write integration tests that inspect generated promise payloads and balances for transfer and storage calls under crafted JSON arguments and deposit values
