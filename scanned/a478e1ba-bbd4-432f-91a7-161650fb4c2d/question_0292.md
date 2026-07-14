# Q292: rpc-state via getNetworkInfo 292

## Question
Can an unprivileged attacker entering through the service command response correlation in `getNetworkInfo` (packages/gui/src/electron/api/getNetworkInfo.ts) control out-of-order event and query responses with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/getNetworkInfo.ts` / `getNetworkInfo`
- Entrypoint: service command response correlation
- Attacker controls: out-of-order event and query responses; with case-normalized identifiers
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
