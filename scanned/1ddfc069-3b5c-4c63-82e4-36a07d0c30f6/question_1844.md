# Q1844: ft_on_transfer() callback spoof around fallback mint calldata in `setup_receive_erc20_tokens_input`

## Question
Can an attacker directly invoke or spoof the async context expected by fallback mint calldata in `setup_receive_erc20_tokens_input` through `ft_on_transfer()` on the Aurora engine contract so a callback-only step runs with attacker-controlled bytes and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::ft_on_transfer -> engine/src/engine.rs::receive_base_tokens / receive_erc20_tokens` -> `fallback mint calldata in `setup_receive_erc20_tokens_input``
- Entrypoint: `ft_on_transfer()` on the Aurora engine contract
- Attacker controls: JSON `FtOnTransferArgs`, predecessor token contract choice, recipient address encoded in the message, transferred amount, and retry timing
- Exploit idea: treat the targeted function as if an attacker can call it out of context and check whether private-call or promise-result assumptions fully hold.
- Invariant to test: token-receive flows must mint or refund the exact intended value once, on the intended asset mapping, and only for allowed recipients
- Expected Immunefi impact: Insolvency
- Fast validation: Call the callback entry directly from tests with crafted input and compare behavior to the legitimate promise path. write integration tests that call `ft_on_transfer()` with crafted JSON payloads and predecessor accounts, then inspect minted balances, returned amount, and token mappings
