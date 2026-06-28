# Q2260: connector ft and storage methods resource exhaustion seeded by JSON parsing of `FtTransferArgs`

## Question
Can an attacker use `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract so that JSON parsing of `FtTransferArgs` keeps creating state, promises, or registrations that the protocol must later pay to maintain, eventually causing Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_transfer / ft_transfer_call / storage_* / return_promise` -> `JSON parsing of `FtTransferArgs``
- Entrypoint: `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract
- Attacker controls: JSON transfer and storage arguments, attached deposit, attached 1 yocto where required, target account IDs, and repeated request ordering
- Exploit idea: look for unbounded public resource creation rooted in the targeted connector step.
- Invariant to test: proxy methods into the NEAR-side connector must preserve exactly one intended account, amount, memo/message, and attached-balance meaning
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Run a high-count local sequence and measure whether protocol-held storage, registration state, or required connector balance grows without safe user-paid bounds. write integration tests that inspect generated promise payloads and balances for transfer and storage calls under crafted JSON arguments and deposit values
