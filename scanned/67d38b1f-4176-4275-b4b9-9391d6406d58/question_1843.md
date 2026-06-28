# Q1843: ft_on_transfer() partial burn or refund at fallback mint calldata in `setup_receive_erc20_tokens_input`

## Question
Can an attacker force fallback mint calldata in `setup_receive_erc20_tokens_input` into a path where value is burned, escrowed, or promised before the success condition is finalized, then reclaim or replay value so the protocol loses funds and suffers Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `fallback mint calldata in `setup_receive_erc20_tokens_input``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: attack ordering between burn/escrow and final success acknowledgement at the named step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Instrument the failing downstream branch and assert burned or escrowed value is either fully restored or never consumed. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
