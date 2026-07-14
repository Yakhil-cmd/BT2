# Q1850: rpc-state via isLocalhost 1850

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `isLocalhost` (packages/gui/src/util/isLocalhost.ts) control RPC error payload shaped like success through a batch of rapid user-accessible actions and drive the sequence fetch -> cache -> refresh -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/isLocalhost.ts` / `isLocalhost`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; through a batch of rapid user-accessible actions
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
