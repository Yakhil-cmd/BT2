# Q1837: ft_on_transfer() connector target confusion in ERC20 receive path in `receive_erc20_tokens`

## Question
Can an attacker route ERC20 receive path in `receive_erc20_tokens` toward the wrong connector account or downstream method through `ft_on_transfer()` on the Aurora engine contract, so a valid-looking request lands in the wrong contract context and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `ERC20 receive path in `receive_erc20_tokens``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: abuse connector account selection and method-name routing near the targeted helper.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Insolvency
- Fast validation: Inspect the generated promise target account and method for crafted inputs and assert they always match the intended operation. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
