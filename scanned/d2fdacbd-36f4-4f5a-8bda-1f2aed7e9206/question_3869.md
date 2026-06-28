# Q3869: silo and mirror enforcement funding shortfall after submit gating in `is_allow_submit`

## Question
Can an attacker make submit gating in `is_allow_submit` consume user value to start an XCC flow but leave the resulting router account underfunded for completion or recovery, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `submit gating in `is_allow_submit``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: strand value by separating initial funding from the minimum viable router balance.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Measure router balance after partial funding and ensure every accepted path leaves enough balance either to complete or to refund safely. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
