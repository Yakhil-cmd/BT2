# Q1770: ft_on_transfer() amount scale split around JSON parsing of `FtOnTransferArgs`

## Question
Can an attacker force JSON parsing of `FtOnTransferArgs` to interpret the same amount under two different units, decimal conventions, or byte widths through `ft_on_transfer()` on the Aurora engine contract, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `JSON parsing of `FtOnTransferArgs``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: attack amount scaling and numeric width at the named connector boundary.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Fuzz amount boundaries and compare the public amount with the actual burned, minted, transferred, or refunded amount. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
