# Q1901: ft_on_transfer() serialization split around metadata and mapping lookups for the incoming token

## Question
Can an unprivileged attacker use `ft_on_transfer()` on the Aurora engine contract with JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing and make metadata and mapping lookups for the incoming token serialize one recipient, amount, or account identity while the downstream promise or engine path interprets another, leading to Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `metadata and mapping lookups for the incoming token`
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: abuse a serialization boundary at the targeted step to split what the user intended from what the downstream connector sees.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Insolvency
- Fast validation: Inspect the exact promise payload or downstream calldata created from the crafted input and compare it with the original user intent. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
