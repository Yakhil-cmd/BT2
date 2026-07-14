# Q3400: rpc-state via selectApiConfig 3400

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `selectApiConfig` (packages/api-react/src/slices/api.ts) control subscription event for a different wallet/fingerprint with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/slices/api.ts` / `selectApiConfig`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with case-normalized identifiers
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
