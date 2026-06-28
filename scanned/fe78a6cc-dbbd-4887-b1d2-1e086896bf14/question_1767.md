# Q1767: ft_on_transfer() malformed JSON or borsh at JSON parsing of `FtOnTransferArgs`

## Question
Can an attacker send malformed but parseable JSON or borsh through `ft_on_transfer()` on the Aurora engine contract so that JSON parsing of `FtOnTransferArgs` accepts a structurally valid payload with a semantically dangerous meaning, leading to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `JSON parsing of `FtOnTransferArgs``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: look for edge-case decoding that preserves syntax but changes business meaning at the targeted step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Fuzz the relevant JSON or borsh fields and assert downstream promise payloads and state changes remain semantically canonical. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
