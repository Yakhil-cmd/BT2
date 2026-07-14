# Q648: rpc-state via toSnakeCase 648

## Question
Can an unprivileged attacker entering through the service command response correlation in `toSnakeCase` (packages/gui/src/electron/utils/toSnakeCase.ts) control out-of-order event and query responses with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/toSnakeCase.ts` / `toSnakeCase`
- Entrypoint: service command response correlation
- Attacker controls: out-of-order event and query responses; with hidden Unicode characters
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
