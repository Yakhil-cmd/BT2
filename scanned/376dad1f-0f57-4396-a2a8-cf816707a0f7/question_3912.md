# Q3912: silo and mirror enforcement retry recovery gap at private-call enforcement in `mirror_erc20_token_callback`

## Question
Can an attacker push private-call enforcement in `mirror_erc20_token_callback` into a failure state that cannot be retried safely but also does not restore consumed funds or metadata, leaving recoverability broken and causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `private-call enforcement in `mirror_erc20_token_callback``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: force the targeted step into a non-idempotent failed state.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Cause failure before and after the targeted mutation and verify every failed state has one safe retry or full refund path. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
