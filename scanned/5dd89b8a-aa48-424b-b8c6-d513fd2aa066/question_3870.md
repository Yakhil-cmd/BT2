# Q3870: silo and mirror enforcement address encoding edge in submit gating in `is_allow_submit`

## Question
Can an attacker use edge-case address encodings through public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods so that submit gating in `is_allow_submit` truncates, collides, or reformats the target differently from later consumers, causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `submit gating in `is_allow_submit``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: attack address encoding and formatting at the targeted XCC boundary.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Fuzz edge-case EVM addresses and compare the encoded address used in every downstream promise and stored metadata field. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
