# Q3587: rpc-state via TradeRecord 3587

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `TradeRecord` (packages/api/src/@types/TradeRecord.ts) control out-of-order event and query responses through a batch of rapid user-accessible actions and drive the sequence validate input -> normalize payload -> call RPC so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/TradeRecord.ts` / `TradeRecord`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; through a batch of rapid user-accessible actions
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
