# Q3881: silo and mirror enforcement private-call bypass at token receive gating in `is_allow_receive_erc20_tokens`

## Question
Can an unprivileged attacker directly invoke or otherwise spoof the private async context expected by token receive gating in `is_allow_receive_erc20_tokens` through public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods, so router, callback, or wNEAR-moving logic runs out of context and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `token receive gating in `is_allow_receive_erc20_tokens``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: treat the targeted XCC helper as attacker-callable and check whether context checks fully prevent misuse.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Directly call the function with crafted args and compare behavior to the legitimate async path before and after promise completion. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
