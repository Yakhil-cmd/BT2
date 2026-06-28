# Q3904: silo and mirror enforcement wNEAR source confusion around private-call enforcement in `mirror_erc20_token_callback`

## Question
Can an attacker use public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods to make private-call enforcement in `mirror_erc20_token_callback` unwrap, fund, or refund using the wrong wNEAR source or amount source, leading to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `private-call enforcement in `mirror_erc20_token_callback``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: misroute wNEAR source selection at the targeted funding or withdraw step.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Track which address loses wNEAR and which router/sub-account gains NEAR under crafted inputs and failure branches. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
