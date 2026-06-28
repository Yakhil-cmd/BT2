# Q1862: ft_on_transfer() double-apply path at amount-to-return handling after errors

## Question
Can an attacker trigger amount-to-return handling after errors twice for one logical action through retries, repeated calls, or callback reuse from `ft_on_transfer()` on the Aurora engine contract, so burn, mint, refund, or registration state is applied more than once and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `amount-to-return handling after errors`
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: look for a one-to-many application of one user action around the targeted connector step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Replay the same logical action across repeated calls and callback timing variations and assert supply, mappings, and balances remain single-applied. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
