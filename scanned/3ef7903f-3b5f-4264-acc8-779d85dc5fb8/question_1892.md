# Q1892: ft_on_transfer() mapping collision around silo allowlist enforcement in `is_allow_receive_erc20_tokens`

## Question
Can an attacker choose inputs through `ft_on_transfer()` on the Aurora engine contract so that silo allowlist enforcement in `is_allow_receive_erc20_tokens` collides two distinct users, assets, or registrations into one storage key or one effective route, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `silo allowlist enforcement in `is_allow_receive_erc20_tokens``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: target the storage key or mapping derivation consumed by the named step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Search for colliding identifiers under fuzzed account and asset inputs and assert the contract always preserves one-to-one mappings. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
