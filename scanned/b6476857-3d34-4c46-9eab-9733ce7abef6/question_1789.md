# Q1789: ft_on_transfer() recipient mismatch in connector-versus-ERC20 branch selection using `predecessor_account_id`

## Question
Can an attacker make connector-versus-ERC20 branch selection using `predecessor_account_id` route value to a different recipient than the one visible at the public entrypoint, via encoding, truncation, or mapping confusion, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `connector-versus-ERC20 branch selection using `predecessor_account_id``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: exploit a mismatch between public recipient intent and downstream recipient bytes or addresses.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Use crafted recipient values and compare the entrypoint-visible recipient with the recipient encoded in downstream calls or minted balances. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
