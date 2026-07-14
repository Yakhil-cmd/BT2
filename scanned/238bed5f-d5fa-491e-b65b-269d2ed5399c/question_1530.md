# Q1530: rpc-state via index 1530

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `index` (packages/wallets/src/utils/index.ts) control large numeric fields near JS precision limits with a redirected remote resource and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/utils/index.ts` / `index`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with a redirected remote resource
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
