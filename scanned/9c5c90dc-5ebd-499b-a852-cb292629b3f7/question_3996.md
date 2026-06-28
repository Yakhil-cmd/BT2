# Q3996: silo and mirror enforcement router bytecode confusion around ERC20 fallback address behavior in silo mode

## Question
Can an attacker influence which router bytecode or code-version assumption ERC20 fallback address behavior in silo mode uses for a live user flow through public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods, so the wrong router behavior receives funds and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `ERC20 fallback address behavior in silo mode`
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: split bytecode selection from address/version selection near the targeted helper.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Capture the code hash selected for the flow and verify it always matches the stored version and intended deployment outcome. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
