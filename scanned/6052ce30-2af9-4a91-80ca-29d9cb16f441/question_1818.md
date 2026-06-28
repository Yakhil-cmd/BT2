# Q1818: ft_on_transfer() revert/success split after base-token receive path in `receive_base_tokens`

## Question
Can an attacker make base-token receive path in `receive_base_tokens` treat a downstream revert as success, or a downstream success as failure, so mint, refund, or registration logic goes down the wrong branch and leads to Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `base-token receive path in `receive_base_tokens``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: attack success detection and branch selection around the targeted callback or promise result.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Insolvency
- Fast validation: Simulate both success and failure promise outcomes and assert the chosen branch matches the real downstream result every time. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
