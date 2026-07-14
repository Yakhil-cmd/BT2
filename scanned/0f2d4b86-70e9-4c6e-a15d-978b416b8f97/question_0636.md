# Q636: rpc-state via ipcMainHandle 636

## Question
Can an unprivileged attacker entering through the service command response correlation in `ipcMainHandle` (packages/gui/src/electron/utils/ipcMainHandle.ts) control large numeric fields near JS precision limits with case-normalized identifiers and drive the sequence import -> parse -> preview -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/ipcMainHandle.ts` / `ipcMainHandle`
- Entrypoint: service command response correlation
- Attacker controls: large numeric fields near JS precision limits; with case-normalized identifiers
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
