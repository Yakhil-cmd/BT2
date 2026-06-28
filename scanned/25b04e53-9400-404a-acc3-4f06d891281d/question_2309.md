# Q2309: connector ft and storage methods recipient mismatch in JSON parsing of `StorageUnregisterArgs`

## Question
Can an attacker make JSON parsing of `StorageUnregisterArgs` route value to a different recipient than the one visible at the public entrypoint, via encoding, truncation, or mapping confusion, causing Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_transfer / ft_transfer_call / storage_* / return_promise` -> `JSON parsing of `StorageUnregisterArgs``
- Entrypoint: `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract
- Attacker controls: JSON transfer and storage arguments, attached deposit, attached 1 yocto where required, target account IDs, and repeated request ordering
- Exploit idea: exploit a mismatch between public recipient intent and downstream recipient bytes or addresses.
- Invariant to test: proxy methods into the NEAR-side connector must preserve exactly one intended account, amount, memo/message, and attached-balance meaning
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Use crafted recipient values and compare the entrypoint-visible recipient with the recipient encoded in downstream calls or minted balances. write integration tests that inspect generated promise payloads and balances for transfer and storage calls under crafted JSON arguments and deposit values
