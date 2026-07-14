# Q536: rpc-state via getServiceKeepState 536

## Question
Can an unprivileged attacker entering through the service command response correlation in `getServiceKeepState` (packages/api-react/src/hooks/useServices.ts) control RPC error payload shaped like success after canceling and reopening the dialog and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/hooks/useServices.ts` / `getServiceKeepState`
- Entrypoint: service command response correlation
- Attacker controls: RPC error payload shaped like success; after canceling and reopening the dialog
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
