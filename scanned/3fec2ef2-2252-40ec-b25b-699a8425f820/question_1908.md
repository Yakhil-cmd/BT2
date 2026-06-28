# Q1908: ft_on_transfer() gas starvation around metadata and mapping lookups for the incoming token

## Question
Can an attacker choose input size or call ordering through `ft_on_transfer()` on the Aurora engine contract so that metadata and mapping lookups for the incoming token creates a promise graph with too little gas to finish safely, stranding funds or state and causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `metadata and mapping lookups for the incoming token`
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: target gas sizing logic attached to the connector promise or callback path.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Run low-prepaid-gas and high-input-size cases and assert the function cannot strand value or half-written mapping state when gas is tight. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
