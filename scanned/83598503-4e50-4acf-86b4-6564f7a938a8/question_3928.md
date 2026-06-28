# Q3928: silo and mirror enforcement code/address split at private-or-owner split in `set_erc20_metadata`

## Question
Can an attacker cause private-or-owner split in `set_erc20_metadata` to pair router code from one version with address metadata from another through public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods, so later calls use mismatched code and value-routing assumptions and lead to Insolvency?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `private-or-owner split in `set_erc20_metadata``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: desynchronize the code-version and address-version state touched by the targeted step.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Insolvency
- Fast validation: Update or fail the code path around the targeted callback and assert the stored version and deployed code hash remain in lockstep. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
