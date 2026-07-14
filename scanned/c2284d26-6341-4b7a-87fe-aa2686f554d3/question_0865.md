# Q865: rpc-state via mojoToCATLocaleString 865

## Question
Can an unprivileged attacker entering through the RTK query cache update in `mojoToCATLocaleString` (packages/core/src/utils/mojoToCATLocaleString.ts) control large numeric fields near JS precision limits with a redirected remote resource and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/utils/mojoToCATLocaleString.ts` / `mojoToCATLocaleString`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; with a redirected remote resource
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
