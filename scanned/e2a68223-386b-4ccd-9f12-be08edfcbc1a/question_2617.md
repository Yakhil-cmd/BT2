# Q2617: rpc-state via CalculateRoyaltiesResponse 2617

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `CalculateRoyaltiesResponse` (packages/api/src/@types/CalculateRoyaltiesResponse.ts) control subscription event for a different wallet/fingerprint after a network switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/CalculateRoyaltiesResponse.ts` / `CalculateRoyaltiesResponse`
- Entrypoint: camel/snake case transform path
- Attacker controls: subscription event for a different wallet/fingerprint; after a network switch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
