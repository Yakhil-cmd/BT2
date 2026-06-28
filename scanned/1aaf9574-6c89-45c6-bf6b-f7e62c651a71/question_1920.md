# Q1920: ft_on_transfer() resource exhaustion seeded by metadata and mapping lookups for the incoming token

## Question
Can an attacker use `ft_on_transfer()` on the Aurora engine contract so that metadata and mapping lookups for the incoming token keeps creating state, promises, or registrations that the protocol must later pay to maintain, eventually causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `metadata and mapping lookups for the incoming token`
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: look for unbounded public resource creation rooted in the targeted connector step.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Run a high-count local sequence and measure whether protocol-held storage, registration state, or required connector balance grows without safe user-paid bounds. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
