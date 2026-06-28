# Q1876: ft_on_transfer() queue or promise stranding at amount-to-return handling after errors

## Question
Can an attacker make amount-to-return handling after errors enqueue a downstream action that can no longer complete or be retried safely, leaving user funds or bridge state stranded and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `amount-to-return handling after errors`
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: target the safe-completion assumptions of the promise created by the named step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Interrupt the downstream action at different stages and assert no user value remains trapped without a valid retry or refund path. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
