# Q2370: connector ft and storage methods amount scale split around attached gas math in `calculate_attached_gas`

## Question
Can an attacker force attached gas math in `calculate_attached_gas` to interpret the same amount under two different units, decimal conventions, or byte widths through `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract, causing Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_transfer / ft_transfer_call / storage_* / return_promise` -> `attached gas math in `calculate_attached_gas``
- Entrypoint: `ft_transfer()`, `ft_transfer_call()`, `storage_deposit()`, `storage_unregister()`, and `storage_withdraw()` on the Aurora engine contract
- Attacker controls: JSON transfer and storage arguments, attached deposit, attached 1 yocto where required, target account IDs, and repeated request ordering
- Exploit idea: attack amount scaling and numeric width at the named connector boundary.
- Invariant to test: proxy methods into the NEAR-side connector must preserve exactly one intended account, amount, memo/message, and attached-balance meaning
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Fuzz amount boundaries and compare the public amount with the actual burned, minted, transferred, or refunded amount. write integration tests that inspect generated promise payloads and balances for transfer and storage calls under crafted JSON arguments and deposit values
