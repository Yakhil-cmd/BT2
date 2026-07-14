# Q849: rpc-state via useLocale 849

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `useLocale` (packages/core/src/hooks/useLocale.ts) control out-of-order event and query responses after a profile switch and drive the sequence select -> edit backing object -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useLocale.ts` / `useLocale`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; after a profile switch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
