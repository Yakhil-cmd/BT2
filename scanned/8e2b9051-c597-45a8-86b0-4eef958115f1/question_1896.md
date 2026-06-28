# Q1896: ft_on_transfer() queue or promise stranding at silo allowlist enforcement in `is_allow_receive_erc20_tokens`

## Question
Can an attacker make silo allowlist enforcement in `is_allow_receive_erc20_tokens` enqueue a downstream action that can no longer complete or be retried safely, leaving user funds or bridge state stranded and causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `silo allowlist enforcement in `is_allow_receive_erc20_tokens``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: target the safe-completion assumptions of the promise created by the named step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Interrupt the downstream action at different stages and assert no user value remains trapped without a valid retry or refund path. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
