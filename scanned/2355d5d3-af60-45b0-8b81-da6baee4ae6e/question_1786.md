# Q1786: ft_on_transfer() duplicate registration through connector-versus-ERC20 branch selection using `predecessor_account_id`

## Question
Can an attacker use `ft_on_transfer()` on the Aurora engine contract so that connector-versus-ERC20 branch selection using `predecessor_account_id` registers the same asset, account, or mapping twice under inconsistent metadata or addresses, breaking canonical mapping invariants and causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `connector-versus-ERC20 branch selection using `predecessor_account_id``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: create a duplicate or conflicting registration state around the targeted helper.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Attempt repeated registration and mixed metadata paths, then assert the canonical mapping stays one-to-one and balances remain intact. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
