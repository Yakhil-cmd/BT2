# Q2606: rpc-state via currentEndpoint 2606

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `currentEndpoint` (packages/api-react/src/utils/onCacheEntryAddedInvalidate.ts) control subscription event for a different wallet/fingerprint with precision-boundary values and drive the sequence open notification -> resolve details -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/utils/onCacheEntryAddedInvalidate.ts` / `currentEndpoint`
- Entrypoint: camel/snake case transform path
- Attacker controls: subscription event for a different wallet/fingerprint; with precision-boundary values
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
