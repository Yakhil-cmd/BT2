# Q3357: rpc-state via SignagePoint 3357

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `SignagePoint` (packages/api/src/@types/SignagePoint.ts) control response object with duplicate camelCase/snake_case keys with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/SignagePoint.ts` / `SignagePoint`
- Entrypoint: daemon RPC response handling
- Attacker controls: response object with duplicate camelCase/snake_case keys; with hidden Unicode characters
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
