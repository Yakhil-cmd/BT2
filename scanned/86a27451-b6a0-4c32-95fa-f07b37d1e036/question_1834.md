# Q1834: ft_on_transfer() cross-asset mixup in ERC20 receive path in `receive_erc20_tokens`

## Question
Can an attacker use `ft_on_transfer()` on the Aurora engine contract to make ERC20 receive path in `receive_erc20_tokens` associate the wrong token contract, metadata, or bridge account with the current action, so one asset is credited or debited as another and causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `ERC20 receive path in `receive_erc20_tokens``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: abuse asset-identity assumptions at the targeted mapping or metadata step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Exercise different token identities around the same flow and assert each path touches only its own balances and metadata. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
