# Q3885: silo and mirror enforcement promise graph underfunding at token receive gating in `is_allow_receive_erc20_tokens`

## Question
Can an attacker make token receive gating in `is_allow_receive_erc20_tokens` construct an underfunded or incomplete promise graph through public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods, so the public action reaches an unrecoverable half-complete state and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `token receive gating in `is_allow_receive_erc20_tokens``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: starve the XCC promise graph of gas or required state after the targeted step.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Vary prepaid gas and callback complexity around the targeted path and assert either full completion or a safe rollback/refund outcome. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
