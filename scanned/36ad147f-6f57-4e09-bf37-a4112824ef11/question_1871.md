# Q1871: ft_on_transfer() idempotence break at amount-to-return handling after errors

## Question
Can an attacker repeat the exact same public request through `ft_on_transfer()` on the Aurora engine contract and make amount-to-return handling after errors treat it as fresh instead of already-consumed state, leading to Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `amount-to-return handling after errors`
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: look for missing idempotence or replay resistance at the targeted connector step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Insolvency
- Fast validation: Replay the same request and assert supply, storage registration, and mappings do not move on the second attempt. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
