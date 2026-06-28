# Q2247: connector ft and storage methods malformed JSON or borsh at JSON parsing of `FtTransferArgs`

## Question
Can an attacker send malformed but parseable JSON or borsh through `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract so that JSON parsing of `FtTransferArgs` accepts a structurally valid payload with a semantically dangerous meaning, leading to Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_transfer / ft_transfer_call / storage_* / return_promise` -> `JSON parsing of `FtTransferArgs``
- Entrypoint: `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract
- Attacker controls: JSON transfer and storage arguments, attached deposit, attached 1 yocto where required, target account IDs, and repeated request ordering
- Exploit idea: look for edge-case decoding that preserves syntax but changes business meaning at the targeted step.
- Invariant to test: proxy methods into the NEAR-side connector must preserve exactly one intended account, amount, memo/message, and attached-balance meaning
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Fuzz the relevant JSON or borsh fields and assert downstream promise payloads and state changes remain semantically canonical. write integration tests that inspect generated promise payloads and balances for transfer and storage calls under crafted JSON arguments and deposit values
