# Q3095: rpc-state via getNetworkInfo 3095

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getNetworkInfo` (packages/gui/src/electron/api/getNetworkInfo.ts) control response object with duplicate camelCase/snake_case keys with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/getNetworkInfo.ts` / `getNetworkInfo`
- Entrypoint: WebSocket event subscription
- Attacker controls: response object with duplicate camelCase/snake_case keys; with hidden Unicode characters
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
