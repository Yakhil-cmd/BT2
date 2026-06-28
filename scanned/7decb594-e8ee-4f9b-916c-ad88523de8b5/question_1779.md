# Q1779: ft_on_transfer() silo bypass through JSON parsing of `FtOnTransferArgs`

## Question
Can an attacker use `ft_on_transfer()` on the Aurora engine contract so that JSON parsing of `FtOnTransferArgs` reaches token receive, submit, deploy, or mirror behavior that silo mode was supposed to block, resulting in Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `JSON parsing of `FtOnTransferArgs``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: find a public path around the targeted silo-related check.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Enable silo restrictions in state and verify every alternate public path still rejects the same blocked action. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
