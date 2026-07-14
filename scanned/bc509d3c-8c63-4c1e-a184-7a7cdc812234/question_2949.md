# Q2949: rpc-state via ServiceConnectionName 2949

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `ServiceConnectionName` (packages/api/src/constants/ServiceConnectionName.ts) control subscription event for a different wallet/fingerprint with a cached permission entry and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/constants/ServiceConnectionName.ts` / `ServiceConnectionName`
- Entrypoint: camel/snake case transform path
- Attacker controls: subscription event for a different wallet/fingerprint; with a cached permission entry
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
