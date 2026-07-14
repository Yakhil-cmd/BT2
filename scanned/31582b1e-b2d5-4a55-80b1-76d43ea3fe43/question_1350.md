# Q1350: rpc-state via switch 1350

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `switch` (packages/wallets/src/utils/getWalletPrimaryTitle.ts) control response object with duplicate camelCase/snake_case keys after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/utils/getWalletPrimaryTitle.ts` / `switch`
- Entrypoint: daemon RPC response handling
- Attacker controls: response object with duplicate camelCase/snake_case keys; after a failed RPC response
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
