# Q1805: ft_on_transfer() promise shape confusion in base-token receive path in `receive_base_tokens`

## Question
Can an attacker make base-token receive path in `receive_base_tokens` observe an unexpected promise count, result index, or result type through `ft_on_transfer()` on the Aurora engine contract, so the wrong branch mints, refunds, or registers state and leads to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `base-token receive path in `receive_base_tokens``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: target assumptions about promise shape and result indexing inside the named connector step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Mock or simulate alternate promise-result layouts and assert the function rejects every malformed layout before mutating value-bearing state. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
